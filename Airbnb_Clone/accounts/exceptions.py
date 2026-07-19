import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)



class ServiceLayerError(Exception):
    """Custom exception for business logic failures in services.py.
    Use this instead of DRF's ValidationError in your service layer to prevent leaky abstractions."""
    pass



def custom_global_exception_handler(exc, context):
    """Custom exception handler that intercepts unhandled exceptions,
    logs them safely, and returns a standardized JSON format."""

    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)

    # Handle our custom ServiceLayerError gracefully as a 400 Bad Request
    if isinstance(exc, ServiceLayerError):
        return Response({"success": False, "message": str(exc)},status=status.HTTP_400_BAD_REQUEST)

    # If response is None, DRF didn't handle it. This is a 500 Internal Server Error.
    if response is None:
        view_name = context['view'].__class__.__name__
        logger.exception("Unexpected error in %s", view_name)
        
        return Response({"success": False,"message": "An unexpected error occurred. Please try again later."}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response