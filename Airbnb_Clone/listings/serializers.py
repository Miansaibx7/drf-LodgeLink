"""
Read-only / reference data:
    PropertyCategorySerializer        -> category filter chips
    AmenitySerializer                 -> single amenity
    AmenityCategorySerializer         -> amenities grouped into sections

Photos ("Upload multiple images"):
    PropertyImageSerializer           -> single photo (read + metadata edit)
    PropertyImageBulkUploadSerializer -> POST several files in one request

Availability calendar:
    PropertyAvailabilitySerializer            -> single calendar day
    PropertyAvailabilityBulkUpdateSerializer  -> block/price a date range

Listing (Property) — three serializers, one per use case, so each endpoint
only pays for the fields it actually needs:
    PropertyListSerializer     -> search results / browse grid (lightweight)
    PropertyMapSerializer      -> map pins (minimal — "Location map" feature)
    PropertyDetailSerializer   -> single listing page (full, read-only)
    PropertyCreateUpdateSerializer -> Add property / Edit property (write)
"""
from typing import Optional

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers

from .models import (Amenity,AmenityCategory,Property,PropertyAvailability,
    PropertyCategory,PropertyImage)

User = get_user_model()


# ============================================================================
# HOST  (minimal, read-only, safe to nest inside listing responses)
# ============================================================================
class HostMiniSerializer(serializers.ModelSerializer):
    """ Lightweight read-only host card nested inside listing responses.
    Adjust the field list if your custom User model uses different names."""

    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'date_joined']
        read_only_fields = fields

    def get_full_name(self, obj) -> str:
        """Return type: str — display name shown on the listing page."""
        first = getattr(obj, 'first_name', '') or ''
        last = getattr(obj, 'last_name', '') or ''
        full_name = f'{first} {last}'.strip()
        return full_name or getattr(obj, 'username', str(obj))



# ============================================================================
# CATEGORIES
# ============================================================================
class PropertyCategorySerializer(serializers.ModelSerializer):
    """Read/write serializer for the homepage category filter chips."""

    class Meta:
        model = PropertyCategory
        fields = ['id', 'name', 'slug', 'icon', 'description', 'is_active', 'order']
        read_only_fields = ['id', 'slug']



# ============================================================================
# AMENITIES
# ============================================================================
class AmenitySerializer(serializers.ModelSerializer):
    """A single amenity, e.g. 'Wifi'. `category` accepts a category ID on write."""

    class Meta:
        model = Amenity
        fields = ['id', 'name', 'icon', 'category', 'is_active']
        read_only_fields = ['id']



class AmenityCategorySerializer(serializers.ModelSerializer):
    """
    Read-only, grouped output for a listing's amenities section — exactly
    how Airbnb renders it (Essentials / Features / Safety, each with a
    nested list of amenities).
    """
    amenities = AmenitySerializer(many=True, read_only=True)

    class Meta:
        model = AmenityCategory
        fields = ['id', 'name', 'order', 'amenities']
        read_only_fields = fields


# ============================================================================
# PROPERTY IMAGES  ("Upload multiple images")
# ============================================================================
class PropertyImageSerializer(serializers.ModelSerializer):
    """
    Represents a single gallery photo.
    Used for: (a) output inside listing detail responses, and
              (b) PATCH-ing metadata (caption / order / is_cover) of an
                  already-uploaded photo via PropertyImageViewSet.
    NOTE: for uploading several NEW files in one request, use
    PropertyImageBulkUploadSerializer below instead — DRF's nested
    writable nested serializers don't handle multiple files under one
    multipart field cleanly, so that's handled with a dedicated serializer."""

    class Meta:
        model = PropertyImage
        fields = ['id', 'property', 'image', 'caption', 'is_cover', 'order', 'created_at']
        read_only_fields = ['id', 'created_at']
        extra_kwargs = {'property': {'write_only': True, 'required': False}}

    def validate_image(self, value):
        """ Return type: UploadedFile
        Rejects oversized files before they ever hit storage/S3. """

        max_size_mb = 8
        if value.size > max_size_mb * 1024 * 1024:
            raise serializers.ValidationError(f'Image file too large. Max size is {max_size_mb}MB.')
        return value

    def update(self, instance, validated_data):
        """ Return type: PropertyImage
        Allows flipping is_cover from the gallery manager UI; the model's
        own save() already guarantees only one cover image per property."""

        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        return instance


class PropertyImageBulkUploadSerializer(serializers.Serializer):
    """ Dedicated serializer for the "Upload multiple images" endpoint, e.g.:
        POST /api/properties/{id}/images/
        multipart/form-data with repeated `images` fields (images=file1,
        images=file2, images=file3 ...)

    Not a ModelSerializer, by design — this is the reliable way to accept
    N files under one field name in DRF. """

    images = serializers.ListField(child=serializers.ImageField(), allow_empty=False, write_only=True,
        help_text='One or more image files sent as repeated multipart fields.')
    
    MAX_IMAGES_PER_REQUEST = 20

    def validate_images(self, value):
        """Return type: list[UploadedFile]
        Caps the batch size so one request can't flood storage/queue workers."""

        if len(value) > self.MAX_IMAGES_PER_REQUEST:
            raise serializers.ValidationError(
                f'You can upload at most {self.MAX_IMAGES_PER_REQUEST} images per request.'
            )
        for image_file in value:
            if image_file.size > 8 * 1024 * 1024:
                raise serializers.ValidationError(
                    f'"{image_file.name}" exceeds the 8MB per-image limit.'
                )
        return value

    def create(self, validated_data):
        """
         Return type: list [PropertyImage]
        Bulk-creates one PropertyImage row per uploaded file against the
        `property` instance passed in via serializer context (the view is
        responsible for permission-checking that the requester owns it).
        The first photo ever uploaded to an empty gallery is auto-flagged
        as the cover image, matching Airbnb's default behaviour.
        """
        property_instance = self.context['property']
        starting_order = property_instance.images.count()
        has_cover_already = property_instance.images.filter(is_cover=True).exists()

        new_images = [
            PropertyImage(
                property=property_instance,
                image=image_file,
                order=starting_order + index,
                is_cover=(not has_cover_already and index == 0),
            )
            for index, image_file in enumerate(validated_data['images'])
        ]
        return PropertyImage.objects.bulk_create(new_images)

    def to_representation(self, instance):
        """
         Return type: dict
        `instance` is the list[PropertyImage] returned by create(); this
        re-serializes each row with PropertyImageSerializer for the response."""

        return {'uploaded_count': len(instance),
            'images': PropertyImageSerializer(instance, many=True, context=self.context).data,
        }


# ============================================================================
# AVAILABILITY CALENDAR
# ============================================================================
class PropertyAvailabilitySerializer(serializers.ModelSerializer):
    """Represents a single day on a listing's availability calendar."""
    effective_price = serializers.SerializerMethodField()

    class Meta:
        model = PropertyAvailability
        fields = [
            'id', 'date', 'status', 'price_override',
            'minimum_stay_override', 'note', 'effective_price',
        ]
        read_only_fields = ['id', 'effective_price']

    def get_effective_price(self, obj) -> str:
        """
         Return type: str
        The actual nightly price for this date (override, or the listing's
        base_price as fallback). Returned as a string for safe JSON
        transport of Decimal values."""

        return str(obj.effective_price)


class PropertyAvailabilityBulkUpdateSerializer(serializers.Serializer):
    """
     Powers calendar bulk-actions: "block these dates", "set weekend
    pricing for this range", etc.
        POST /api/properties/{id}/availability/bulk-update/
        { "start_date": "2026-12-20", "end_date": "2027-01-02",
          "status": "blocked" }
    """
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    status = serializers.ChoiceField(choices=PropertyAvailability.DayStatus.choices, required=False)
    price_override = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False, allow_null=True
    )
    minimum_stay_override = serializers.IntegerField(required=False, allow_null=True, min_value=1)

    MAX_RANGE_DAYS = 730  # guard against accidental multi-year bulk writes

    def validate(self, attrs):
        """
         Return type: dict — the validated attrs.
        Ensures the range is logical, bounded, and that at least one
        updatable field was actually supplied."""

        if attrs['end_date'] < attrs['start_date']:
            raise serializers.ValidationError('end_date must be on or after start_date.')

        span_days = (attrs['end_date'] - attrs['start_date']).days + 1
        if span_days > self.MAX_RANGE_DAYS:
            raise serializers.ValidationError(
                f'Date range too large ({span_days} days). Max is {self.MAX_RANGE_DAYS} days.'
            )

        updatable_fields = {'status', 'price_override', 'minimum_stay_override'}
        if not updatable_fields.intersection(attrs.keys()):
            raise serializers.ValidationError('Provide at least one of: status, price_override, minimum_stay_override.')
        return attrs

    def save(self, **kwargs):
        """Return type: int — number of PropertyAvailability rows written.
        Upserts one row per date in [start_date, end_date], applying only
        the fields the host actually sent (partial update semantics)."""

        property_instance = self.context['property']
        start_date = self.validated_data['start_date']
        end_date = self.validated_data['end_date']

        update_fields = {
            field: self.validated_data[field]
            for field in ('status', 'price_override', 'minimum_stay_override')
            if field in self.validated_data
        }

        affected = 0
        current_date = start_date
        with transaction.atomic():
            while current_date <= end_date:
                PropertyAvailability.objects.update_or_create(
                    property=property_instance,
                    date=current_date,
                    defaults=update_fields,
                )
                affected += 1
                current_date += timezone.timedelta(days=1)

        return affected


# ============================================================================
# PROPERTY — LIST (search result / browse grid)
# ============================================================================
class PropertyListSerializer(serializers.ModelSerializer):
    """ Lightweight serializer for search results / browse grids. Deliberately
    excludes heavy fields (full description, house_rules, full gallery,
    all amenities) so list endpoints stay fast under pagination."""
    cover_image = serializers.SerializerMethodField()
    category_names = serializers.SerializerMethodField()

    class Meta:
        model = Property
        fields = [
            'id', 'title', 'slug', 'property_type', 'room_type',
            'city', 'state', 'country', 'latitude', 'longitude',
            'base_price', 'currency', 'max_guests', 'bedrooms', 'beds', 'bathrooms',
            'average_rating', 'review_count', 'instant_book',
            'cover_image', 'category_names', 'status',
        ]
        read_only_fields = fields

    def get_cover_image(self, obj) -> Optional[str]:
        """Return type: Optional[str] — absolute URL of the main photo, or None if the gallery is empty."""
        image = obj.cover_image
        if not image:
            return None
        request = self.context.get('request')
        return request.build_absolute_uri(image.image.url) if request else image.image.url

    def get_category_names(self, obj) -> list:
        """Return type: list[str] — category chips shown on the search card."""
        return [category.name for category in obj.categories.all()]



# ============================================================================
# PROPERTY — MAP  ("Location map" feature)
# ============================================================================
class PropertyMapSerializer(serializers.ModelSerializer):
    """
     Minimal payload for rendering pins on the search-results map — just
    enough to draw a marker and a small hover-preview card."""

    cover_image = serializers.SerializerMethodField()

    class Meta:
        model = Property
        fields = ['id', 'title', 'latitude', 'longitude', 'base_price', 'currency', 'cover_image']
        read_only_fields = fields

    def get_cover_image(self, obj) -> Optional[str]:
        """Return type: Optional[str] — thumbnail URL shown in the map hover card."""
        image = obj.cover_image
        if not image:
            return None
        request = self.context.get('request')
        return request.build_absolute_uri(image.image.url) if request else image.image.url



# ============================================================================
# PROPERTY — DETAIL  (single listing page, read-only / rich)
# ============================================================================
class PropertyDetailSerializer(serializers.ModelSerializer):
    """
     Full, read-heavy representation for the single listing detail page.
    Nests host info, categories, amenities, and the complete photo gallery
    in one response so the frontend needs exactly one API call to render
    the page."""

    host = HostMiniSerializer(read_only=True)
    categories = PropertyCategorySerializer(many=True, read_only=True)
    amenities = AmenitySerializer(many=True, read_only=True)
    images = PropertyImageSerializer(many=True, read_only=True)
    is_bookable = serializers.SerializerMethodField()

    class Meta:
        model = Property
        fields = [
            'id', 'host', 'title', 'slug', 'description', 'summary',
            'property_type', 'room_type', 'categories', 'amenities', 'images',
            'max_guests', 'bedrooms', 'beds', 'bathrooms',
            'country', 'state', 'city', 'neighborhood', 'address_line', 'zipcode',
            'latitude', 'longitude',
            'base_price', 'currency', 'cleaning_fee', 'service_fee_percentage',
            'weekly_discount_percentage', 'monthly_discount_percentage',
            'included_guests', 'extra_guest_fee', 'security_deposit',
            'min_nights', 'max_nights', 'check_in_time', 'check_out_time',
            'instant_book', 'cancellation_policy', 'house_rules',
            'smoking_allowed', 'pets_allowed', 'parties_allowed',
            'status', 'is_active', 'is_bookable',
            'average_rating', 'review_count', 'booking_count', 'view_count',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'host', 'is_bookable', 'average_rating', 'review_count',
            'booking_count', 'view_count', 'created_at', 'updated_at',
        ]

    def get_is_bookable(self, obj) -> bool:
        """Return type: bool — mirrors Property.is_bookable (published + active + has photos)."""
        return obj.is_bookable


# ============================================================================
# PROPERTY — CREATE / UPDATE  ("Add property" / "Edit property")
# ============================================================================
class PropertyCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Handles:
        POST   /api/properties/            -> create()  ("Add property")
        PUT    /api/properties/{id}/       -> update()  ("Edit property", full)
        PATCH  /api/properties/{id}/       -> update()  ("Edit property", partial)

    - `host` is NEVER accepted from client input — always taken from the
      authenticated request in the view/serializer, preventing a guest
      from creating a listing under someone else's account.
    - `categories` / `amenities` accept lists of primary keys and are
      applied with .set().
    - `images` supports a SMALL number of inline photos on creation (JSON
      body with base64, or a simple multipart case). For real multi-file
      uploads, prefer PropertyImageBulkUploadSerializer — see the note on
      PropertyImageSerializer above.
    - On success, to_representation() returns the same rich payload as
      PropertyDetailSerializer, so the client doesn't need a second GET."""
    
    categories = serializers.PrimaryKeyRelatedField(
        many=True, queryset=PropertyCategory.objects.all(), required=False
    )
    amenities = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Amenity.objects.all(), required=False
    )
    images = PropertyImageSerializer(many=True, required=False)

    class Meta:
        model = Property
        fields = [
            'id', 'title', 'description', 'summary',
            'property_type', 'room_type', 'categories', 'amenities', 'images',
            'max_guests', 'bedrooms', 'beds', 'bathrooms',
            'country', 'state', 'city', 'neighborhood', 'address_line', 'zipcode',
            'latitude', 'longitude',
            'base_price', 'currency', 'cleaning_fee', 'service_fee_percentage',
            'weekly_discount_percentage', 'monthly_discount_percentage',
            'included_guests', 'extra_guest_fee', 'security_deposit',
            'min_nights', 'max_nights', 'check_in_time', 'check_out_time',
            'instant_book', 'cancellation_policy', 'house_rules',
            'smoking_allowed', 'pets_allowed', 'parties_allowed',
            'status', 'is_active',
        ]
        read_only_fields = ['id']

    # ---- Field-level validation --------------------------------------

    def validate_base_price(self, value):
        """Return type: Decimal — must be a positive nightly price."""

        if value <= 0:
            raise serializers.ValidationError('Base price must be greater than 0.')
        return value

    def validate_max_guests(self, value):
        """Return type: int — a listing must sleep at least 1 guest."""
        if value < 1:
            raise serializers.ValidationError('A listing must accommodate at least 1 guest.')
        return value

    def validate_latitude(self, value):
        """Return type: Decimal — sanity-checks the map pin coordinates."""

        if not (-90 <= value <= 90):
            raise serializers.ValidationError('Latitude must be between -90 and 90.')
        return value

    def validate_longitude(self, value):
        """Return type: Decimal sanity-checks the map pin coordinates."""

        if not (-180 <= value <= 180):
            raise serializers.ValidationError('Longitude must be between -180 and 180.')
        return value


    # -------------- Cross-field validation --------------------------------------------------------------------
    def validate(self, attrs):
        """
         Return type: dict the validated attrs (or raises ValidationError).
        Business rules that depend on more than one field at once"""

        min_nights = attrs.get('min_nights', getattr(self.instance, 'min_nights', 1))
        max_nights = attrs.get('max_nights', getattr(self.instance, 'max_nights', 365))
        if min_nights > max_nights:
            raise serializers.ValidationError({'min_nights': 'min_nights cannot be greater than max_nights.'})

        included_guests = attrs.get('included_guests', getattr(self.instance, 'included_guests', 1))
        max_guests = attrs.get('max_guests', getattr(self.instance, 'max_guests', 1))
        if included_guests > max_guests:
            raise serializers.ValidationError({'included_guests': 'included_guests cannot exceed max_guests.'})

        # Publishing requires a minimum photo gallery, exactly like Airbnb
        # (which enforces 5 photos minimum before a listing can go live).
        target_status = attrs.get('status', getattr(self.instance, 'status', Property.Status.DRAFT))
        if target_status == Property.Status.PUBLISHED:
            existing_images = self.instance.images.count() if self.instance else 0
            incoming_images = len(attrs.get('images', []))
            if existing_images + incoming_images < 5:
                raise serializers.ValidationError(
                    {'status': 'A listing needs at least 5 photos before it can be published.'}
                )

        return attrs

    # ---- Create / Update (nested writes) -------------------------------

    @transaction.atomic
    def create(self, validated_data):
        """
        Return type: Property
        Creates the listing, attaches the host from the authenticated
        request, applies M2M relations, creates any inline photos, and
        pre-seeds a year of calendar rows so the listing is immediately
        manageable/bookable."""

        categories = validated_data.pop('categories', [])
        amenities = validated_data.pop('amenities', [])
        images_data = validated_data.pop('images', [])

        request = self.context['request']
        property_instance = Property.objects.create(host=request.user, **validated_data)

        if categories:
            property_instance.categories.set(categories)
        if amenities:
            property_instance.amenities.set(amenities)

        for index, image_data in enumerate(images_data):
            PropertyImage.objects.create(
                property=property_instance,
                order=index,
                is_cover=(index == 0),
                **image_data,
            )

        property_instance.generate_availability(days=365)

        return property_instance

    @transaction.atomic
    def update(self, instance, validated_data):
        """
        Return type: Property
        Updates scalar fields in place, replaces M2M sets only when the
        client actually sent them (so a PATCH without 'amenities' doesn't
        wipe existing amenities), and appends any newly-included inline
        images. Existing photos are managed via PropertyImageViewSet, not
        overwritten here.
        """
        categories = validated_data.pop('categories', None)
        amenities = validated_data.pop('amenities', None)
        images_data = validated_data.pop('images', None)

        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()

        if categories is not None:
            instance.categories.set(categories)
        if amenities is not None:
            instance.amenities.set(amenities)

        if images_data:
            starting_order = instance.images.count()
            for index, image_data in enumerate(images_data):
                PropertyImage.objects.create(
                    property=instance,
                    order=starting_order + index,
                    **image_data,
                )

        return instance

    def to_representation(self, instance):
        """
        Return type: dict
        After a successful create/update, respond with the rich
        PropertyDetailSerializer payload (resolved host, categories,
        amenities, image URLs) instead of echoing back raw write input."""

        return PropertyDetailSerializer(instance, context=self.context).data