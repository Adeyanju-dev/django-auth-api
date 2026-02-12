from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        custom_response = {
            "success": False,
            "message": "An error occurred",
            "errors": response.data
        }

        # If DRF already has a 'detail'
        if isinstance(response.data, dict) and "detail" in response.data:
            custom_response["message"] = response.data["detail"]

        response.data = custom_response

    return response
