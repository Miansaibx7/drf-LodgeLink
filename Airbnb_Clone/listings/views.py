"""
listings/views.py

Airbnb Clone — LISTINGS APP (DRF Views)
============================================================================
Pairs with listings/models.py and listings/serializers.py.

Requires:
    pip install django-filter          # search/filter backend used below
    pip install drf-nested-routers     # only if you wire PropertyImageViewSet
                                        # as a nested route (see note at the
                                        # bottom of this file for urls.py).

Endpoint map
----------------------------------------------------------------------------
PropertyViewSet          (router-registered at /api/properties/)
    GET    /properties/                       list (public, published only)
    POST   /properties/                       create   -> "Add property"
    GET    /properties/{id}/                  retrieve
    PUT    /properties/{id}/                  update   -> "Edit property"
    PATCH  /properties/{id}/                  partial update
    DELETE /properties/{id}/                  destroy  -> "Delete property" (soft)
    GET    /properties/map/                   lightweight pins for map search
    GET    /properties/mine/                  the logged-in host's own listings
    POST   /properties/{id}/publish/          shortcut: status -> published
    POST   /properties/{id}/archive/          shortcut: status -> archived
    POST   /properties/{id}/images/           "Upload multiple images"
    GET    /properties/{id}/availability/     read the calendar
    POST   /properties/{id}/availability/bulk-update/   block/price a range

PropertyImageViewSet      (nested at /api/properties/{property_pk}/photos/{id}/)
    PATCH  .../photos/{id}/                   edit caption/order/is_cover
    DELETE .../photos/{id}/                   remove a single photo

PropertyCategoryViewSet, AmenityCategoryViewSet, AmenityViewSet
    Public read for everyone; write access restricted to staff — these
    are reference/lookup data used to populate the listing wizard's
    category picker and amenities checklist.
============================================================================
"""

from django_filters import rest_framework as django_filters
from django.utils import timezone

from rest_framework import filters, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from .models import (
    Amenity,
    AmenityCategory,
    Property,
    PropertyCategory,
    PropertyImage,
)
from .serializers import (
    AmenityCategorySerializer,
    AmenitySerializer,
    PropertyAvailabilityBulkUpdateSerializer,
    PropertyAvailabilitySerializer,
    PropertyCategorySerializer,
    PropertyCreateUpdateSerializer,
    PropertyDetailSerializer,
    PropertyImageBulkUploadSerializer,
    PropertyImageSerializer,
    PropertyListSerializer,
    PropertyMapSerializer,
)


# ============================================================================
# PERMISSIONS
# ============================================================================

class IsHostOrReadOnly(permissions.BasePermission):
    """
    Anyone (including anonymous users) can browse listings.
    Only the listing's own host — or staff — may create/edit/delete it.
    """

    def has_permission(self, request, view):
        """Return type: bool — must be authenticated to write; open to read."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        """Return type: bool — object-level check: only the owning host (or staff) may modify."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.host_id == request.user.id or request.user.is_staff


class IsAdminOrReadOnly(permissions.BasePermission):
    """Public read access for reference/lookup data; staff-only writes."""

    def has_permission(self, request, view):
        """Return type: bool"""
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)


# ============================================================================
# PAGINATION
# ============================================================================

class PropertyPagination(PageNumberPagination):
    """Standard pagination for listing search results."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# ============================================================================
# FILTERING  (search endpoint: price range, guests, category, amenities...)
# ============================================================================

class PropertyFilter(django_filters.FilterSet):
    """
    Enables querystrings like:
        /api/properties/?city=Istanbul&min_price=40&max_price=200
        &guests=4&property_type=apartment&room_type=entire_place
        &instant_book=true&category=beachfront&amenity=3&amenity=7
    """
    min_price = django_filters.NumberFilter(field_name='base_price', lookup_expr='gte')
    max_price = django_filters.NumberFilter(field_name='base_price', lookup_expr='lte')
    guests = django_filters.NumberFilter(field_name='max_guests', lookup_expr='gte')
    category = django_filters.CharFilter(field_name='categories__slug', lookup_expr='iexact')
    amenity = django_filters.ModelMultipleChoiceFilter(
        field_name='amenities', queryset=Amenity.objects.all()
    )

    class Meta:
        model = Property
        fields = [
            'city', 'country', 'property_type', 'room_type',
            'instant_book', 'min_price', 'max_price', 'guests', 'category', 'amenity',
        ]


# ============================================================================
# PROPERTY  — the core listing CRUD + custom actions
# ============================================================================

class PropertyViewSet(viewsets.ModelViewSet):
    """
    Handles the full listing lifecycle: Add / Edit / Delete property, plus
    map search, host dashboard, image upload, and the availability calendar.
    """
    permission_classes = [IsHostOrReadOnly]
    pagination_class = PropertyPagination
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    filter_backends = [django_filters.DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = PropertyFilter
    search_fields = ['title', 'description', 'city', 'country', 'neighborhood']
    ordering_fields = ['base_price', 'average_rating', 'created_at', 'review_count']
    ordering = ['-created_at']

    # ---- Queryset / serializer selection --------------------------------

    def get_queryset(self):
        """
        Return type: QuerySet[Property]
        Public traffic (list/map) only ever sees published + active
        listings. Detail/edit/delete rely on object-level permissions
        (IsHostOrReadOnly) rather than queryset filtering, so a host can
        still retrieve their own draft to keep editing it.
        """
        queryset = Property.objects.select_related('host').prefetch_related(
            'images', 'categories', 'amenities'
        )
        if self.action in ('list', 'map'):
            return queryset.filter(status=Property.Status.PUBLISHED, is_active=True)
        return queryset

    def get_serializer_class(self):
        """Return type: type[Serializer] — right-sized serializer per action."""
        if self.action == 'list':
            return PropertyListSerializer
        if self.action == 'map':
            return PropertyMapSerializer
        if self.action in ('create', 'update', 'partial_update'):
            return PropertyCreateUpdateSerializer
        return PropertyDetailSerializer  # retrieve, mine, publish, archive

    # ---- Standard CRUD overrides ----------------------------------------

    def retrieve(self, request, *args, **kwargs):
        """
        Return type: Response
        Increments the denormalized view_count on every detail-page hit —
        a cheap signal later used for "trending" / "popular" sorting.
        """
        instance = self.get_object()
        Property.objects.filter(pk=instance.pk).update(view_count=instance.view_count + 1)
        instance.refresh_from_db(fields=['view_count'])
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def perform_destroy(self, instance):
        """
        Return type: None
        "Delete property" soft-deletes (see SoftDeleteModel on the model
        side) so booking/payout history tied to this listing survives.
        Pass ?hard=true for a genuine hard delete (staff/GDPR use only).
        """
        hard_delete = self.request.query_params.get('hard') == 'true' and self.request.user.is_staff
        instance.delete(hard_delete=hard_delete)

    # ---- Custom actions ---------------------------------------------------

    @action(detail=False, methods=['get'])
    def map(self, request):
        """
        Return type: Response
        GET /api/properties/map/?<same filters as list>
        Lightweight pin data for every matching published listing — powers
        the split-view "Location map" search experience.
        """
        queryset = self.filter_queryset(self.get_queryset())
        serializer = PropertyMapSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def mine(self, request):
        """
        Return type: Response
        GET /api/properties/mine/
        The authenticated host's own listings — including drafts and
        archived ones — for their "My listings" management dashboard.
        """
        queryset = Property.all_objects.filter(host=request.user).select_related('host').prefetch_related(
            'images', 'categories', 'amenities'
        ).order_by('-created_at')

        page = self.paginate_queryset(queryset)
        target = page if page is not None else queryset
        serializer = PropertyDetailSerializer(target, many=True, context={'request': request})
        return self.get_paginated_response(serializer.data) if page is not None else Response(serializer.data)

    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """
        Return type: Response
        POST /api/properties/{id}/publish/
        Convenience shortcut for flipping status -> published without
        resending the whole listing payload. Still runs the serializer's
        "5 photos minimum" validation.
        """
        property_instance = self.get_object()
        serializer = PropertyCreateUpdateSerializer(
            property_instance,
            data={'status': Property.Status.PUBLISHED},
            partial=True,
            context={'request': request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        """
        Return type: Response
        POST /api/properties/{id}/archive/
        Lets a host pause a listing (hide it from search) without deleting it.
        """
        property_instance = self.get_object()
        property_instance.status = Property.Status.ARCHIVED
        property_instance.is_active = False
        property_instance.save(update_fields=['status', 'is_active'])
        serializer = PropertyDetailSerializer(property_instance, context={'request': request})
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='images')
    def upload_images(self, request, pk=None):
        """
        Return type: Response (201 Created)
        POST /api/properties/{id}/images/   (multipart, repeated `images` field)
        The "Upload multiple images" endpoint.
        """
        property_instance = self.get_object()
        self._check_is_host(request, property_instance)

        serializer = PropertyImageBulkUploadSerializer(
            data=request.data, context={'property': property_instance, 'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'], url_path='availability')
    def availability(self, request, pk=None):
        """
        Return type: Response
        GET /api/properties/{id}/availability/?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD
        Returns the calendar for the requested range (defaults to the next
        90 days) — feeds the date-picker on the listing page.
        """
        property_instance = self.get_object()
        today = timezone.localdate()
        start_date = request.query_params.get('start_date') or today
        end_date = request.query_params.get('end_date') or (today + timezone.timedelta(days=90))

        queryset = property_instance.availability.filter(date__gte=start_date, date__lte=end_date)
        serializer = PropertyAvailabilitySerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='availability/bulk-update')
    def bulk_update_availability(self, request, pk=None):
        """
        Return type: Response
        POST /api/properties/{id}/availability/bulk-update/
        Body: {"start_date": "...", "end_date": "...", "status": "blocked"}
        Lets the host block a date range or set custom pricing across it in
        a single call, instead of one request per day.
        """
        property_instance = self.get_object()
        self._check_is_host(request, property_instance)

        serializer = PropertyAvailabilityBulkUpdateSerializer(
            data=request.data, context={'property': property_instance}
        )
        serializer.is_valid(raise_exception=True)
        affected_count = serializer.save()
        return Response({'updated_days': affected_count}, status=status.HTTP_200_OK)

    # ---- Internal helpers ---------------------------------------------

    @staticmethod
    def _check_is_host(request, property_instance):
        """
        Return type: None (raises PermissionDenied on failure)
        Shared ownership guard reused by the nested image/availability
        actions above (DRF's object-level permission check only runs
        automatically for the 6 standard actions, not custom @action methods).
        """
        if property_instance.host_id != request.user.id and not request.user.is_staff:
            raise PermissionDenied("You do not have permission to modify this listing.")


# ============================================================================
# PROPERTY IMAGES  — manage a single already-uploaded photo
# ============================================================================

class PropertyImageViewSet(viewsets.ModelViewSet):
    """
    Nested under a property: /api/properties/{property_pk}/photos/{id}/
    Only PATCH (edit caption/order/is_cover) and DELETE are exposed here —
    creating new photos goes through PropertyViewSet.upload_images instead,
    since that's the endpoint built for multi-file uploads.
    Requires the URL to supply `property_pk` (see nested router note below).
    """
    serializer_class = PropertyImageSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'patch', 'delete']

    def get_queryset(self):
        """Return type: QuerySet[PropertyImage] — scoped to the property in the URL."""
        return PropertyImage.objects.filter(property_id=self.kwargs['property_pk'])

    def check_object_permissions(self, request, obj):
        """
        Return type: None (raises PermissionDenied on failure)
        Only the owning host (or staff) may edit/delete a listing's photos.
        """
        super().check_object_permissions(request, obj)
        if obj.property.host_id != request.user.id and not request.user.is_staff:
            raise PermissionDenied("You do not have permission to modify this listing's photos.")


# ============================================================================
# REFERENCE / LOOKUP DATA  — categories & amenities
# ============================================================================

class PropertyCategoryViewSet(viewsets.ModelViewSet):
    """
    Public read for the homepage category filter chips; admin-managed writes.
    """
    queryset = PropertyCategory.objects.filter(is_active=True)
    serializer_class = PropertyCategorySerializer
    permission_classes = [IsAdminOrReadOnly]
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']


class AmenityCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public, read-only: amenities grouped into sections (Essentials,
    Features, Safety...) exactly as shown in the listing wizard / filters.
    """
    queryset = AmenityCategory.objects.prefetch_related('amenities').all()
    serializer_class = AmenityCategorySerializer
    permission_classes = [permissions.AllowAny]


class AmenityViewSet(viewsets.ModelViewSet):
    """
    Flat amenity CRUD, admin-managed. Used to populate the "select
    amenities" step of the Add/Edit property wizard.
    """
    queryset = Amenity.objects.select_related('category').filter(is_active=True)
    serializer_class = AmenitySerializer
    permission_classes = [IsAdminOrReadOnly]
    filter_backends = [filters.SearchFilter]
    search_fields = ['name', 'category__name']


# ============================================================================
# URL WIRING NOTE (not this file, but needed for the endpoints above to work)
# ============================================================================
# listings/urls.py would look like:
#
#   from rest_framework.routers import DefaultRouter
#   from rest_framework_nested.routers import NestedDefaultRouter
#   from . import views
#
#   router = DefaultRouter()
#   router.register('properties', views.PropertyViewSet, basename='property')
#   router.register('categories', views.PropertyCategoryViewSet, basename='category')
#   router.register('amenity-categories', views.AmenityCategoryViewSet, basename='amenity-category')
#   router.register('amenities', views.AmenityViewSet, basename='amenity')
#
#   properties_router = NestedDefaultRouter(router, 'properties', lookup='property')
#   properties_router.register('photos', views.PropertyImageViewSet, basename='property-photos')
#
#   urlpatterns = router.urls + properties_router.urls
# ============================================================================