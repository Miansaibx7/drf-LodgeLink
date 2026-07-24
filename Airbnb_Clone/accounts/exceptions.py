import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from rest_framework import status

logger = logging.getLogger(__name__)


class ServiceLayerError(APIException):
    """Custom exception for business logic failures in services.py.
    Use this instead of DRF's ValidationError in the service layer so the
    service layer has zero dependency on DRF request/response internals."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Service layer encountered an error.'
    default_code = 'service_error'


# FIX (bug): the original file defined `custom_global_exception_handler`
# TWICE. In Python, the second `def` silently overwrites the first — the
# first implementation (which special-cased ServiceLayerError with a 400 and
# a bare {"success": False, "message": ...} body, and logged unhandled
# exceptions with the view name) was completely dead code. Only the second
# definition below was ever actually wired up via
# REST_FRAMEWORK['EXCEPTION_HANDLER']. This merges the useful behavior of
# both into a single implementation and removes the shadowed duplicate.
def custom_global_exception_handler(exc, context):
    """
    Custom exception handler that intercepts unhandled exceptions, logs them
    safely, and returns a standardized JSON envelope:
        {"success": False, "message": "...", "errors": {...} | None}
    """
    response = exception_handler(exc, context)

    # DRF didn't recognize this exception at all -> unhandled 500.
    if response is None:
        view = context.get('view')
        view_name = view.__class__.__name__ if view else "UnknownView"
        logger.exception("Unhandled exception in %s", view_name)
        return Response(
            {"success": False, "message": "An unexpected error occurred. Please try again later.", "errors": None},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    custom_data = {"success": False, "message": "An error occurred.", "errors": None}

    if isinstance(exc, ServiceLayerError):
        custom_data['message'] = str(exc.detail)
    elif isinstance(response.data, dict):
        if 'detail' in response.data:
            custom_data['message'] = str(response.data['detail'])
        else:
            custom_data['message'] = 'Validation Error'
            custom_data['errors'] = response.data
    elif isinstance(response.data, list):
        # FIX: response.data[0] can itself be a dict/ErrorDetail, not
        # guaranteed to be directly str()-able the way the caller expects;
        # coerce explicitly so the "message" field is always a plain string.
        custom_data['message'] = str(response.data[0]) if response.data else 'Validation Error'
        custom_data['errors'] = response.data

    response.data = custom_data
    return response