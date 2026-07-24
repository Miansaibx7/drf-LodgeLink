"""Account Deletion Requests (GDPR compliance)."""
import logging
from datetime import timedelta
from typing import Optional
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.request import Request
from django.db import transaction

from ..models import AccountDeletionRequest, User
from ..exceptions import ServiceLayerError

logger = logging.getLogger(__name__)


# ===================== Serializers =====================

class AccountDeletionRequestSerializer(serializers.Serializer):
    reason = serializers.CharField(required=False, allow_blank=True)
    confirm = serializers.BooleanField(required=True)

    def validate_confirm(self, value: bool) -> bool:
        if not value:
            raise serializers.ValidationError("You must confirm the deletion request.")
        return value


class AccountDeletionCancelSerializer(serializers.Serializer):
    """No input fields required; kept for symmetry / future extension (e.g. a reason-for-cancel field)."""
    pass


class AccountDeletionStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountDeletionRequest
        fields = ('id', 'reason', 'scheduled_for', 'completed', 'completed_at', 'cancelled', 'created_at')
        read_only_fields = fields


# ===================== Service Layer =====================

class AccountDeletionService:
    """Business logic for account deletion requests."""

    @staticmethod
    @transaction.atomic
    def create_deletion_request(user: User, reason: str, confirm: bool) -> AccountDeletionRequest:
        if not confirm:
            raise ServiceLayerError("Deletion not confirmed.")

        # FIX (concurrency): lock any existing pending row for this user so two
        # simultaneous "delete my account" clicks can't both pass this check
        # and create two AccountDeletionRequest rows.
        existing = AccountDeletionRequest.objects.select_for_update().filter(
            user=user, completed=False, cancelled=False
        ).first()
        if existing:
            raise ServiceLayerError("You already have a pending deletion request.")

        scheduled_for = timezone.now() + timedelta(days=7)

        request_obj = AccountDeletionRequest.objects.create(
            user=user,
            reason=reason,
            scheduled_for=scheduled_for,
            completed=False,
            cancelled=False
        )

        logger.info("Deletion request created for user %s, scheduled for %s", user.email, scheduled_for)
        return request_obj

    @staticmethod
    @transaction.atomic
    def cancel_deletion_request(user: User) -> None:
        request_obj = AccountDeletionRequest.objects.select_for_update().filter(
            user=user, completed=False, cancelled=False
        ).first()
        if not request_obj:
            raise ServiceLayerError("No pending deletion request found.")

        request_obj.cancelled = True
        request_obj.save(update_fields=['cancelled'])
        logger.info("Deletion request cancelled for user %s", user.email)

    @staticmethod
    def get_user_deletion_status(user: User) -> Optional[AccountDeletionRequest]:
        return AccountDeletionRequest.objects.filter(
            user=user, completed=False, cancelled=False
        ).first()

    @staticmethod
    @transaction.atomic
    def complete_deletion_request(request_obj: AccountDeletionRequest) -> None:
        """
        Actually delete the user account. This must be invoked by a scheduled
        job (Celery beat / cron management command), not by any request/response
        cycle.

        MISSING PIECE (flagging, not silently fixing): nothing in this codebase
        currently calls this method. There is no Celery worker/beat config, no
        management command, and no cron entry wired up anywhere in the files
        you shared. As written, AccountDeletionRequest rows will sit at
        completed=False forever and accounts will never actually be deleted
        after the 7-day grace period. You need one of:
          1. A Celery periodic task (celery beat) that queries
             AccountDeletionRequest.objects.filter(scheduled_for__lte=now(),
             completed=False, cancelled=False) and calls this method for each, or
          2. A Django management command (`manage.py process_account_deletions`)
             invoked by a system cron job on the same schedule.
        """
        # FIX (bug): lock the row before re-checking state to avoid a race
        # where cancel_deletion_request() and this job run at nearly the same
        # moment.
        request_obj = AccountDeletionRequest.objects.select_for_update().get(pk=request_obj.pk)
        if request_obj.completed or request_obj.cancelled:
            return

        user = request_obj.user
        request_obj.complete()
        user.delete()
        logger.info("Account for user %s has been permanently deleted.", user.email)


# ===================== Views =====================

class AccountDeletionRequestView(APIView):
    """Create a deletion request for the authenticated user (7-day grace period)."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = AccountDeletionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        deletion_request = AccountDeletionService.create_deletion_request(
            user=request.user,
            reason=serializer.validated_data.get('reason', ''),
            confirm=serializer.validated_data['confirm']
        )

        return Response({
            'success': True,
            'message': 'Deletion request submitted. Your account will be deleted on {}.'.format(
                deletion_request.scheduled_for.strftime('%Y-%m-%d %H:%M:%S')
            ),
            'request_id': deletion_request.id,
            'scheduled_for': deletion_request.scheduled_for
        }, status=status.HTTP_201_CREATED)


class AccountDeletionCancelView(APIView):
    """Cancel a pending deletion request."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = AccountDeletionCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        AccountDeletionService.cancel_deletion_request(user=request.user)
        return Response({'success': True, 'message': 'Deletion request cancelled successfully.'}, status=status.HTTP_200_OK)


class AccountDeletionStatusView(APIView):
    """Get the current deletion request status."""
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        request_obj = AccountDeletionService.get_user_deletion_status(user=request.user)
        if request_obj:
            serializer = AccountDeletionStatusSerializer(request_obj)
            return Response({'success': True, 'data': serializer.data}, status=status.HTTP_200_OK)
        return Response(
            {'success': True, 'message': 'No active deletion request found.', 'data': None},
            status=status.HTTP_200_OK
        )