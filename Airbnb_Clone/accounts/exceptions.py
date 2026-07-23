import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from rest_framework import status

logger = logging.getLogger(__name__)


    
class ServiceLayerError(APIException):
    """Custom exception for business logic failures in services.py.
    Use this instead of DRF's ValidationError in your service layer to prevent leaky abstractions."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Service layer encountered an error.'
    default_code = 'service_error'



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


def custom_global_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        custom_data = {
            'success': False,
            'message': 'An error occurred.',
            'errors': None
        }

        if isinstance(exc, ServiceLayerError):
            custom_data['message'] = str(exc.detail)
        elif hasattr(response, 'data') and isinstance(response.data, dict):
            if 'detail' in response.data:
                custom_data['message'] = response.data['detail']
            else:
                custom_data['message'] = 'Validation Error'
                custom_data['errors'] = response.data
        elif hasattr(response, 'data') and isinstance(response.data, list):
            custom_data['message'] = response.data[0]
            custom_data['errors'] = response.data

        response.data = custom_data

    return response