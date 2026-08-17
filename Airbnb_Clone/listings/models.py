"""
listings/models.py

Airbnb Clone — LISTINGS APP
============================================================================
Author   : Senior Django / DRF Developer
Scope    : "Second stage — Listings branch"
Covers   : Add / Edit / Delete property, multiple image uploads, property
           categories, pricing engine, availability calendar, amenities,
           and location data for map rendering.

Design notes (read before wiring up serializers/views):
----------------------------------------------------------------------------
1. UUID primary keys are used on public-facing models (Property, Image)
   instead of auto-increment ints. This avoids leaking sequential IDs
   (competitor scraping, enumeration attacks) through the DRF API — exactly
   what Airbnb does with its listing IDs.

2. Soft delete is used for `Property` instead of a hard DB delete. "Delete
   property" in the real product just hides the listing (bookings, reviews,
   and payout history must survive for legal/accounting reasons). A
   `hard_delete=True` escape hatch is provided for admin/GDPR use cases.

3. Pricing lives on the Property model (base price + fees + discounts) AND
   can be overridden per-day via `PropertyAvailability.price_override`
   (weekend/holiday pricing) — this mirrors Airbnb's real pricing engine.

4. Location uses plain lat/lng DecimalFields so this works out of the box
   on any Postgres/MySQL/SQLite setup with no extra system packages. If
   PostGIS is available in your infra, swap to `gis.PointField` (commented
   below) to get true "search properties within X km" queries for free.

5. Multiple image upload is modeled as a separate `PropertyImage` table
   (one-to-many), NOT a JSON/array field — this is required so DRF can
   support per-image ordering, captions, and a "cover photo" flag, and so
   nested serializers can create/update/delete individual images.

6. Two extra models most tutorials forget but Airbnb genuinely has:
   - `PropertyAvailability` (the actual calendar — not just min/max nights)
   - `AmenityCategory` (Airbnb groups amenities into sections: Essentials,
     Features, Location, Safety — not a flat list)

7. Everything needed for the NEXT branch (bookings/reviews) is intentionally
   left out of this app (no Booking/Review models here) to keep listings
   decoupled — but `average_rating`, `review_count`, and `booking_count`
   are kept as denormalized counters on Property, updated via signals from
   those apps later, so listing search/serialization stays fast.
============================================================================
"""

import uuid
from decimal import Decimal

from django.conf import settings
from django.core.validators import (
    FileExtensionValidator,
    MaxValueValidator,
    MinValueValidator,
)
from django.db import models
from django.utils import timezone
from django.utils.text import slugify


# ============================================================================
# ABSTRACT BASE MODELS (reused across the app — DRY)
# ============================================================================

class UUIDModel(models.Model):
    """Swaps the default auto-increment PK for a UUID (safer to expose via API)."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class TimeStampedModel(models.Model):
    """Adds created_at / updated_at to any model that inherits it."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ['-created_at']


class SoftDeleteManager(models.Manager):
    """Default manager: automatically excludes soft-deleted rows."""
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)


class SoftDeleteModel(models.Model):
    """
    Gives a model "Delete property" behaviour without losing history.
    `Property.objects` -> only live listings.
    `Property.all_objects` -> everything, including deleted (for admin/audit).
    """
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = SoftDeleteManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False, hard_delete=False):
        """
        Soft-deletes by default (sets is_deleted=True).
        Pass hard_delete=True to actually remove the row from the DB
        (e.g. admin cleanup jobs / right-to-erasure requests).
        """
        if hard_delete:
            return super().delete(using=using, keep_parents=keep_parents)
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=['is_deleted', 'deleted_at'])
        return (1, {self.__class__.__name__: 1})

    def restore(self):
        """Undo a soft delete — lets a host 'unarchive' a listing."""
        self.is_deleted = False
        self.deleted_at = None
        self.save(update_fields=['is_deleted', 'deleted_at'])


# ============================================================================
# CATEGORIES  (Airbnb's homepage filter icons: Beachfront, Cabins, Trending…)
# ============================================================================
class PropertyCategory(models.Model):
    """Browse-by-category tags shown as icons in the search filter bar."""
    
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=120, unique=True, blank=True)
    icon = models.ImageField(upload_to='categories/icons/', blank=True, null=True)
    description = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0, help_text="Display order in the filter bar")

    class Meta:
        verbose_name = 'Property Category'
        verbose_name_plural = 'Property Categories'
        ordering = ['order', 'name']

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        """Auto-generates the slug from the name if not supplied."""
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)


# ============================================================================
# AMENITIES  (grouped into sections, exactly like Airbnb's listing page)
# ============================================================================

class AmenityCategory(models.Model):
    """Groups amenities into sections: Essentials, Features, Safety, Location…"""

    name = models.CharField(max_length=100, unique=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name_plural = 'Amenity Categories'
        ordering = ['order']

    def __str__(self):
        return self.name


class Amenity(models.Model):
    """A single amenity, e.g. 'Wifi', 'Pool', 'Smoke alarm'."""

    category = models.ForeignKey(AmenityCategory, related_name='amenities', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    icon = models.CharField(max_length=100, blank=True,
        help_text="Icon key for the frontend icon library, e.g. 'wifi', 'pool'")
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = 'Amenities'
        unique_together = ('category', 'name')
        ordering = ['category', 'name']

    def __str__(self):
        return f'{self.name} ({self.category.name})'


# ============================================================================
# PROPERTY  (the core "listing")
# ============================================================================

def property_image_upload_path(instance, filename):
    """Keeps uploaded photos organised per-property and collision-free."""
    return f'properties/{instance.property.id}/images/{uuid.uuid4()}_{filename}'


class Property(UUIDModel, TimeStampedModel, SoftDeleteModel):
    """
    The main listing model. Everything a host fills in during
    'Add property' / 'Edit property' lives here or on a related model.
    """

    # ---- Choice sets ----------------------------------------------------
    class PropertyType(models.TextChoices):
        APARTMENT = 'apartment', 'Apartment'
        HOUSE = 'house', 'House'
        VILLA = 'villa', 'Villa'
        CONDO = 'condo', 'Condominium'
        CABIN = 'cabin', 'Cabin'
        COTTAGE = 'cottage', 'Cottage'
        LOFT = 'loft', 'Loft'
        GUESTHOUSE = 'guesthouse', 'Guesthouse'
        BOUTIQUE_HOTEL = 'hotel', 'Boutique Hotel'
        FARM_STAY = 'farm', 'Farm Stay'
        HOUSEBOAT = 'houseboat', 'Houseboat'
        TREEHOUSE = 'treehouse', 'Treehouse'
        OTHER = 'other', 'Other'

    class RoomType(models.TextChoices):
        ENTIRE_PLACE = 'entire_place', 'Entire place'
        PRIVATE_ROOM = 'private_room', 'Private room'
        SHARED_ROOM = 'shared_room', 'Shared room'
        HOTEL_ROOM = 'hotel_room', 'Hotel room'

    class Status(models.TextChoices):
        DRAFT = 'draft', 'Draft'                        # host mid-wizard, not public
        PENDING_REVIEW = 'pending_review', 'Pending Review'  # optional admin moderation
        PUBLISHED = 'published', 'Published'             # live & bookable
        SUSPENDED = 'suspended', 'Suspended'              # taken down by admin (policy violation)
        ARCHIVED = 'archived', 'Archived'                # host paused it themselves

    class CancellationPolicy(models.TextChoices):
        FLEXIBLE = 'flexible', 'Flexible'
        MODERATE = 'moderate', 'Moderate'
        STRICT = 'strict', 'Strict'
        SUPER_STRICT = 'super_strict', 'Super Strict'

    # ---- Ownership --------------------------------------------------------
    host = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='properties',
        on_delete=models.CASCADE,
        help_text="The user who owns/manages this listing",
    )

    # ---- Core info ----------------------------------------------------
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=280, unique=True, blank=True)
    description = models.TextField()
    summary = models.CharField(
        max_length=500, blank=True,
        help_text="Short teaser shown on search result cards"
    )
    property_type = models.CharField(
        max_length=20, choices=PropertyType.choices, default=PropertyType.APARTMENT
    )
    room_type = models.CharField(
        max_length=20, choices=RoomType.choices, default=RoomType.ENTIRE_PLACE
    )
    categories = models.ManyToManyField(
        PropertyCategory, related_name='properties', blank=True
    )

    # ---- Capacity -------------------------------------------------------
    max_guests = models.PositiveSmallIntegerField(validators=[MinValueValidator(1)])
    bedrooms = models.PositiveSmallIntegerField(default=1)
    beds = models.PositiveSmallIntegerField(default=1)
    bathrooms = models.DecimalField(
        max_digits=3, decimal_places=1, default=Decimal('1.0'),
        help_text="Supports halves, e.g. 1.5 bathrooms"
    )

    # ---- Location (drives the "Location map" feature) --------------------
    country = models.CharField(max_length=100)
    state = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100)
    neighborhood = models.CharField(max_length=150, blank=True)
    address_line = models.CharField(
        max_length=255,
        help_text="Exact street address — only reveal to guest after booking is confirmed"
    )
    zipcode = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(
        max_digits=9, decimal_places=6,
        validators=[MinValueValidator(-90), MaxValueValidator(90)],
    )
    longitude = models.DecimalField(
        max_digits=9, decimal_places=6,
        validators=[MinValueValidator(-180), MaxValueValidator(180)],
    )
    # If PostGIS is available in your infrastructure, prefer this instead of
    # separate lat/lng fields — it unlocks native "within X km" geo queries:
    #
    #   from django.contrib.gis.db import models as gis_models
    #   location = gis_models.PointField(geography=True, srid=4326)

    # ---- Amenities --------------------------------------------------------
    amenities = models.ManyToManyField(Amenity, related_name='properties', blank=True)

    # ---- Pricing (the "Pricing" feature) -----------------------------
    base_price = models.DecimalField(
        max_digits=10, decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Nightly price before fees/discounts"
    )
    currency = models.CharField(max_length=3, default='USD')
    cleaning_fee = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    service_fee_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, default=Decimal('0.00'),
        help_text="Platform service fee %, applied at checkout"
    )
    weekly_discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    monthly_discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    included_guests = models.PositiveSmallIntegerField(
        default=1, help_text="Number of guests included in base_price"
    )
    extra_guest_fee = models.DecimalField(
        max_digits=10, decimal_places=2, default=Decimal('0.00'),
        help_text="Fee per night, per guest above included_guests"
    )
    security_deposit = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))

    # ---- Stay rules -----------------------------------------------------
    min_nights = models.PositiveSmallIntegerField(default=1)
    max_nights = models.PositiveSmallIntegerField(default=365)
    check_in_time = models.TimeField(default='15:00')
    check_out_time = models.TimeField(default='11:00')
    instant_book = models.BooleanField(
        default=False, help_text="If True, guests can book without host approval"
    )
    cancellation_policy = models.CharField(
        max_length=20, choices=CancellationPolicy.choices, default=CancellationPolicy.MODERATE
    )
    house_rules = models.TextField(blank=True, help_text="Free-text extra rules from the host")
    smoking_allowed = models.BooleanField(default=False)
    pets_allowed = models.BooleanField(default=False)
    parties_allowed = models.BooleanField(default=False)

    # ---- Status / visibility --------------------------------------------
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    is_active = models.BooleanField(
        default=True, help_text="Host quick-toggle to hide/show without changing status"
    )

    # ---- Denormalized stats (kept in sync via signals from other apps) --
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=Decimal('0.00'))
    review_count = models.PositiveIntegerField(default=0)
    booking_count = models.PositiveIntegerField(default=0)
    view_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name_plural = 'Properties'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['city', 'country']),
            models.Index(fields=['status', 'is_active']),
            models.Index(fields=['latitude', 'longitude']),
            models.Index(fields=['host']),
        ]

    def __str__(self):
        return f'{self.title} — {self.city}, {self.country}'

    def save(self, *args, **kwargs):
        """Auto-generates a unique, SEO-friendly slug on first save."""
        if not self.slug:
            base_slug = slugify(self.title)
            slug = base_slug
            counter = 1
            while Property.all_objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f'{base_slug}-{counter}'
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    # ---- Convenience helpers used by serializers/views -------------------

    @property
    def cover_image(self):
        """Returns the photo flagged as cover, falling back to the first
        uploaded image. Used as the thumbnail in search results.
        Return type: PropertyImage | None"""
        return self.images.filter(is_cover=True).first() or self.images.first()

    @property
    def is_bookable(self):
        """A listing is bookable only if published, active, not soft-deleted,
        and has at least one photo (Airbnb enforces a 5-photo minimum in
        production — enforce that in the serializer's validate()).
        Return type: bool """
        return (self.status == self.Status.PUBLISHED and self.is_active
            and not self.is_deleted and self.images.exists())

    def total_price_for_stay(self, nights: int, guests: int = 1) -> Decimal:
        """Quick price estimate for `nights` nights and `guests` guests.
        This is a convenience calculator for listing pages/search
        previews. The bookings app should own the authoritative,
        tax-inclusive checkout total (using PropertyAvailability price
        overrides date-by-date) once that branch is built.
        Return type: Decimal (rounded to 2 dp)"""

        if nights <= 0:
            return Decimal('0.00')

        total = self.base_price * nights

        if guests > self.included_guests:
            total += (guests - self.included_guests) * self.extra_guest_fee * nights

        if nights >= 28 and self.monthly_discount_percentage:
            total -= total * (self.monthly_discount_percentage / Decimal('100'))
        elif nights >= 7 and self.weekly_discount_percentage:
            total -= total * (self.weekly_discount_percentage / Decimal('100'))

        total += self.cleaning_fee
        total += total * (self.service_fee_percentage / Decimal('100'))

        return total.quantize(Decimal('0.01'))

    def generate_availability(self, days: int = 365):
        """Bulk-creates `PropertyAvailability` rows for the next `days` days,
        defaulting to AVAILABLE. Call this right after a listing is
        published so the calendar has data to render immediately.
        Return type: int (number of rows created)"""
        existing_dates = set(self.availability.values_list('date', flat=True))
        today = timezone.localdate()
        new_rows = [PropertyAvailability(property=self, date=today + timezone.timedelta(days=i))
            for i in range(days)
            if (today + timezone.timedelta(days=i)) not in existing_dates]
        created = PropertyAvailability.objects.bulk_create(new_rows)
        return len(created)


# ============================================================================
# PROPERTY IMAGES  ("Upload multiple images")
# ============================================================================
class PropertyImage(UUIDModel, TimeStampedModel):
    """One row per photo. A one-to-many table (rather than a JSON list field)
    so DRF nested serializers can add/reorder/delete individual images and
    the frontend gallery can request a specific display order."""

    property = models.ForeignKey(Property, related_name='images', on_delete=models.CASCADE)
    image = models.ImageField(upload_to=property_image_upload_path,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp'])])
    caption = models.CharField(max_length=255, blank=True)
    is_cover = models.BooleanField(default=False, help_text="Main thumbnail shown in search results & listing header")
    order = models.PositiveIntegerField(default=0, help_text="Controls gallery display order")

    class Meta:
        ordering = ['order', 'created_at']
        indexes = [models.Index(fields=['property', 'is_cover'])]

    def __str__(self):
        return f'Image for {self.property.title}'

    def save(self, *args, **kwargs):
        """Guarantees at most one cover image per property."""
        if self.is_cover:
            PropertyImage.objects.filter(
                property=self.property, is_cover=True
            ).exclude(pk=self.pk).update(is_cover=False)
        super().save(*args, **kwargs)


# ============================================================================
# AVAILABILITY CALENDAR
# ============================================================================
class PropertyAvailability(models.Model):
    """One row per (property, date). This is the real, queryable calendar that
    powers 1) the date-picker on the listing page and 2) per-date price
    overrides (weekends/holidays) — not just a min/max-nights rule."""

    class DayStatus(models.TextChoices):
        AVAILABLE = 'available', 'Available'
        BOOKED = 'booked', 'Booked'
        BLOCKED = 'blocked', 'Blocked by host'

    property = models.ForeignKey(Property, related_name='availability', on_delete=models.CASCADE)
    date = models.DateField()
    status = models.CharField(max_length=10, choices=DayStatus.choices, default=DayStatus.AVAILABLE)
    price_override = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True,
        help_text="Custom nightly price for this date; falls back to base_price if empty")
    minimum_stay_override = models.PositiveSmallIntegerField(null=True, blank=True,
        help_text="Overrides Property.min_nights for this specific date")
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name_plural = 'Property Availability'
        unique_together = ('property', 'date')
        ordering = ['date']
        indexes = [models.Index(fields=['property', 'date', 'status'])]

    def __str__(self):
        return f'{self.property.title} — {self.date} ({self.get_status_display()})'

    @property
    def effective_price(self) -> Decimal:
        """Return type: Decimal
        The price actually charged for this date — the override if one is
        set, otherwise the property's standard nightly base_price."""

        return self.price_override if self.price_override is not None else self.property.base_price

    @property
    def is_available(self) -> bool:
        """Return type: bool — True only if bookable on this exact date."""
        return self.status == self.DayStatus.AVAILABLE