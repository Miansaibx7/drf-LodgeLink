"""
listings/admin.py

Airbnb Clone — LISTINGS APP (Django Admin)
============================================================================
Gives staff a working back-office for the listings app while the frontend
is still being built: manage properties, moderate/suspend listings, review
photo galleries, adjust the availability calendar, and maintain the
category/amenity reference data.
============================================================================
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (Amenity,AmenityCategory,Property,PropertyAvailability,PropertyCategory,PropertyImage,)

# ============================================================================
# INLINES  (edit related rows directly on the Property admin page)
# ============================================================================

class PropertyImageInline(admin.TabularInline):
    """Lets staff review/reorder/delete a listing's photo gallery inline."""
    model = PropertyImage
    extra = 0
    fields = ['image_preview', 'image', 'caption', 'is_cover', 'order']
    readonly_fields = ['image_preview']
    ordering = ['order']

    def image_preview(self, obj):
        """Return type: str (safe HTML) — small thumbnail so staff don't have to open each file."""
        if obj.image:
            return format_html('<img src="{}" style="height:60px;width:auto;border-radius:4px;" />', obj.image.url)
        return '—'
    image_preview.short_description = 'Preview'


class PropertyAvailabilityInline(admin.TabularInline):
    """
    Read-mostly peek at the calendar from the Property page. Bulk editing
    should go through the API's bulk-update action, not one row at a time
    here — capped to a small page so this doesn't render 365 rows by default.
    """
    model = PropertyAvailability
    extra = 0
    fields = ['date', 'status', 'price_override', 'minimum_stay_override']
    ordering = ['date']

    def get_queryset(self, request):
        """Return type: QuerySet[PropertyAvailability] — only show the next 30 days inline."""
        from django.utils import timezone
        qs = super().get_queryset(request)
        today = timezone.localdate()
        return qs.filter(date__gte=today, date__lte=today + timezone.timedelta(days=30))

    def has_add_permission(self, request, obj=None):
        """Return type: bool — discourage adding single rows manually; use generate_availability()/API instead."""
        return False


# ============================================================================
# PROPERTY  (the main admin screen)
# ============================================================================

@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'host', 'city', 'country', 'property_type', 'room_type',
        'base_price', 'currency', 'status', 'is_active', 'average_rating',
        'review_count', 'cover_thumbnail', 'created_at',
    ]
    list_filter = [
        'status', 'is_active', 'property_type', 'room_type',
        'instant_book', 'cancellation_policy', 'country', 'is_deleted',
    ]
    search_fields = ['title', 'description', 'city', 'country', 'host__email', 'host__username']
    autocomplete_fields = ['host']
    filter_horizontal = ['categories', 'amenities']
    readonly_fields = [
        'id', 'slug', 'created_at', 'updated_at', 'average_rating',
        'review_count', 'booking_count', 'view_count', 'is_deleted', 'deleted_at',
    ]
    inlines = [PropertyImageInline, PropertyAvailabilityInline]
    actions = ['publish_listings', 'suspend_listings', 'archive_listings', 'seed_availability_calendar']
    list_per_page = 25

    fieldsets = (
        ('Ownership & Identity', {
            'fields': ('id', 'host', 'title', 'slug', 'description', 'summary')
        }),
        ('Classification', {
            'fields': ('property_type', 'room_type', 'categories', 'amenities')
        }),
        ('Capacity', {
            'fields': ('max_guests', 'bedrooms', 'beds', 'bathrooms')
        }),
        ('Location', {
            'fields': (
                'country', 'state', 'city', 'neighborhood',
                'address_line', 'zipcode', 'latitude', 'longitude',
            )
        }),
        ('Pricing', {
            'fields': (
                'base_price', 'currency', 'cleaning_fee', 'service_fee_percentage',
                'weekly_discount_percentage', 'monthly_discount_percentage',
                'included_guests', 'extra_guest_fee', 'security_deposit',
            )
        }),
        ('Stay Rules', {
            'fields': (
                'min_nights', 'max_nights', 'check_in_time', 'check_out_time',
                'instant_book', 'cancellation_policy', 'house_rules',
                'smoking_allowed', 'pets_allowed', 'parties_allowed',
            )
        }),
        ('Status & Visibility', {
            'fields': ('status', 'is_active', 'is_deleted', 'deleted_at')
        }),
        ('Stats (read-only, updated by other apps/signals)', {
            'fields': ('average_rating', 'review_count', 'booking_count', 'view_count')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )

    def get_queryset(self, request):
        """Return type: QuerySet[Property] — admin must see soft-deleted rows too, unlike the public API."""
        return Property.all_objects.select_related('host').prefetch_related('images', 'categories')

    def cover_thumbnail(self, obj):
        """Return type: str (safe HTML) — quick visual cue in the changelist without opening each listing."""
        image = obj.cover_image
        if image:
            return format_html(
                '<img src="{}" style="height:40px;width:auto;border-radius:4px;" />', image.image.url
            )
        return '—'
    cover_thumbnail.short_description = 'Cover'

    # ---- Bulk admin actions ---------------------------------------------

    @admin.action(description='Publish selected listings')
    def publish_listings(self, request, queryset):
        """Return type: None — bulk-flip status to PUBLISHED (skips the API's 5-photo check; use with judgement)."""
        updated = queryset.update(status=Property.Status.PUBLISHED, is_active=True)
        self.message_user(request, f'{updated} listing(s) published.')

    @admin.action(description='Suspend selected listings (policy violation)')
    def suspend_listings(self, request, queryset):
        """Return type: None — takes listings off the public site immediately."""
        updated = queryset.update(status=Property.Status.SUSPENDED, is_active=False)
        self.message_user(request, f'{updated} listing(s) suspended.')

    @admin.action(description='Archive selected listings')
    def archive_listings(self, request, queryset):
        """Return type: None — host-style pause, applied in bulk by staff."""
        updated = queryset.update(status=Property.Status.ARCHIVED, is_active=False)
        self.message_user(request, f'{updated} listing(s) archived.')

    @admin.action(description='Seed 1 year of availability calendar rows')
    def seed_availability_calendar(self, request, queryset):
        """Return type: None — runs Property.generate_availability() for each selected listing."""
        total_created = 0
        for property_instance in queryset:
            total_created += property_instance.generate_availability(days=365)
        self.message_user(request, f'{total_created} calendar day(s) created across selected listings.')


# ============================================================================
# PROPERTY IMAGES  (also manageable standalone, e.g. to search across all listings)
# ============================================================================

@admin.register(PropertyImage)
class PropertyImageAdmin(admin.ModelAdmin):
    list_display = ['property', 'caption', 'is_cover', 'order', 'image_preview', 'created_at']
    list_filter = ['is_cover']
    search_fields = ['property__title', 'caption']
    autocomplete_fields = ['property']
    readonly_fields = ['id', 'created_at', 'image_preview']

    def image_preview(self, obj):
        """Return type: str (safe HTML)"""
        if obj.image:
            return format_html(
                '<img src="{}" style="height:80px;width:auto;border-radius:4px;" />', obj.image.url
            )
        return '—'
    image_preview.short_description = 'Preview'


# ============================================================================
# AVAILABILITY  (standalone screen — useful for support staff resolving disputes)
# ============================================================================

@admin.register(PropertyAvailability)
class PropertyAvailabilityAdmin(admin.ModelAdmin):
    list_display = ['property', 'date', 'status', 'price_override', 'minimum_stay_override']
    list_filter = ['status']
    search_fields = ['property__title']
    autocomplete_fields = ['property']
    date_hierarchy = 'date'
    list_per_page = 50


# ============================================================================
# CATEGORIES & AMENITIES  (reference/lookup data)
# ============================================================================

@admin.register(PropertyCategory)
class PropertyCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'is_active', 'order']
    list_editable = ['is_active', 'order']
    search_fields = ['name']
    prepopulated_fields = {'slug': ('name',)}


class AmenityInline(admin.TabularInline):
    """Manage a category's amenities directly on the AmenityCategory page."""
    model = Amenity
    extra = 1
    fields = ['name', 'icon', 'is_active']


@admin.register(AmenityCategory)
class AmenityCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'order', 'amenity_count']
    list_editable = ['order']
    search_fields = ['name']
    inlines = [AmenityInline]

    def amenity_count(self, obj):
        """Return type: int — quick count so staff know a section isn't empty before publishing it."""
        return obj.amenities.count()
    amenity_count.short_description = 'Amenities'


@admin.register(Amenity)
class AmenityAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'icon', 'is_active']
    list_filter = ['category', 'is_active']
    search_fields = ['name', 'category__name']
    autocomplete_fields = ['category']