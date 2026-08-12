from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from accounts.models import TimeStampedModel  # if you have it there

class Listing(TimeStampedModel):
    """Property / room / experience listing."""
    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        PENDING = 'pending', 'Pending Approval'
        SOLD = 'sold', 'Sold'
        INACTIVE = 'inactive', 'Inactive'

    title = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    location = models.CharField(max_length=255)
    # Optional: latitude/longitude for maps
    lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    lng = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

    # Relationships
    host = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='listings')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)

    # Images can be handled via a separate Image model (or use django-imagekit)
    # For simplicity, we'll add a single cover image field
    cover_image = models.ImageField(upload_to='listings/covers/', blank=True, null=True)

    # Metadata
    max_guests = models.PositiveSmallIntegerField(default=1)
    bedrooms = models.PositiveSmallIntegerField(default=1)
    beds = models.PositiveSmallIntegerField(default=1)
    bathrooms = models.DecimalField(max_digits=3, decimal_places=1, default=1.0)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['host', 'status']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return self.title