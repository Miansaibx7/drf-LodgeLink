import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

from rest_framework.exceptions import (APIException, AuthenticationFailed, MethodNotAllowed,
    NotAuthenticated, NotFound, ParseError, PermissionDenied, Throttled)

logger = logging.getLogger(__name__)



class ServiceLayerError(APIException):
    """ Custom exception raised by the service layer..
    Purpose:
    - Keeps the service layer independent of DRF serializers/views.
    - Allows services.py to raise business-logic errors without importing DRF ValidationError.
    Example:
        raise ServiceLayerError("Email is already registered.") """

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Service layer encountered an error."
    default_code = "service_error"



def extract_first_error(errors):
    """ Recursively extract the first readable validation error string.
    Examples:
        {"email": ["Already exists"]} -> "email: Already exists"
        {"profile": {"bio": ["Too long"]}} -> "profile.bio: Too long"
        ["Invalid request"] -> "Invalid request" """
    
    if isinstance(errors, dict):
        for field, messages in errors.items():

            if isinstance(messages, dict):
                sub_error = extract_first_error(messages)
                return f"{field}.{sub_error}"
            elif isinstance(messages, (list, tuple)) and messages:
                return f"{field}: {messages[0]}"
            return f"{field}: {messages}"

    elif isinstance(errors, (list, tuple)) and errors:
        return extract_first_error(errors[0]) if isinstance(errors[0], (dict, list)) else str(errors[0])
    return str(errors) if errors else "Validation Error"



def custom_global_exception_handler(exc, context):
    """ Global DRF Exception Handler. Every API response follows the same format:
    Success:
        { "success": True, ... }
    Error:
        {"success": False, "message": "...", "errors": {...} | None}. """
    
    response = exception_handler(exc, context)

    # Unhandled Internal Server Exceptions (500)
    if response is None:
        view = context.get("view")
        view_name = view.__class__.__name__ if view else "UnknownView"

        logger.exception("Unhandled exception in %s", view_name)

        return Response({"success": False, "message": "An unexpected error occurred. Please try again later.", "errors": None},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    custom_data = {"success": False, "message": "An error occurred.","errors": None}

   
    # Service Layer Errors
    if isinstance(exc, ServiceLayerError):
        if isinstance(exc.detail, (dict, list)):
            custom_data["message"] = extract_first_error(exc.detail)
            custom_data["errors"] = exc.detail
        else:
            custom_data["message"] = str(exc.detail)

    # Explicit DRF Request & Auth Errors
    elif isinstance(exc,(AuthenticationFailed, NotAuthenticated, PermissionDenied, NotFound, MethodNotAllowed),):
        custom_data["message"] = str(exc.detail)

    elif isinstance(exc, ParseError):
        custom_data["message"] = "Invalid JSON data."

    elif isinstance(exc, Throttled):
        # Retains DRF's built-in wait duration in the message
        custom_data["message"] = str(exc.detail)


    # Serializer Validation Errors
    elif isinstance(response.data, dict):

        if "detail" in response.data:
            custom_data["message"] = str(response.data["detail"])
        else:
            custom_data["message"] = extract_first_error(response.data)
            custom_data["errors"] = response.data

    elif isinstance(response.data, list):
        custom_data["message"] = extract_first_error(response.data)
        custom_data["errors"] = response.data
    else:
        # DRF's default handler shouldn't ever produce a response.data that's neither dict nor list, but if a
        # custom renderer or a future DRF version ever does, silently
        # falling through to the generic "An error occurred." with no trace would make this impossible to debug later.
        logger.warning("Unexpected response.data type in exception handler: %r (exc=%r)",type(response.data), exc,)

    # Log Handled Client Errors
    logger.warning("%s (%s): %s", exc.__class__.__name__, response.status_code, custom_data["message"])

    response.data = custom_data
    return response