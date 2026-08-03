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

from ..models import AccountDeletionRequest, User, AuditLog
from ..exceptions import ServiceLayerError
from ..otp_logic.utils import extract_request_data
from ..otp_logic.services import _log_audit

logger = logging.getLogger(__name__)


# ======================================== Serializers ========================================================================
class AccountDeletionRequestSerializer(serializers.Serializer):
    # FIX: added max_length -- previously unbounded, allowing arbitrarily
    # long text into AccountDeletionRequest.reason (a TextField). Cheap
    # defensive cap; adjust the number to whatever your product actually
    # needs to display.
    reason = serializers.CharField(required=False, allow_blank=True, max_length=1000)
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
    def create_deletion_request(user: User, reason: str, confirm: bool, request_data: dict = None) -> AccountDeletionRequest:
        """Create a pending deletion request with a 7-day grace period.
        Logs an ACCOUNT_DELETE AuditLog entry (status: 'requested')."""
        if not confirm:
            raise ServiceLayerError("Deletion not confirmed.")

        # FIX (concurrency, real bug): select_for_update() can only lock a
        # ROW THAT ALREADY EXISTS. The previous version locked the
        # AccountDeletionRequest queryset -- but the exact race this is
        # meant to prevent (two simultaneous "delete my account" clicks)
        # is precisely the case where NO such row exists yet for either
        # request to lock. Both concurrent calls would see existing=None,
        # both pass the check, and both create a row -- silently producing
        # two AccountDeletionRequest rows for the same user, bypassing the
        # duplicate-request guard entirely. This is the same class of bug
        # found and fixed in BaseOAuthLoginSerializer earlier in this
        # review. Fix: lock the User row itself (which definitely exists),
        # so two concurrent calls for the same user are fully serialized
        # regardless of whether a pending request already exists.
        user = User.objects.select_for_update().get(pk=user.pk)

        existing = AccountDeletionRequest.objects.filter(
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
        # FIX (missing audit trail): AuditLog.Action already defines
        # ACCOUNT_DELETE specifically for this feature, but nothing in
        # this file ever created an entry. Requesting deletion is a
        # security/compliance-relevant action -- there should be a record
        # of who asked, and when.
        _log_audit(user, AuditLog.Action.ACCOUNT_DELETE, request_data,
                   {"status": "requested", "scheduled_for": scheduled_for.isoformat(), "reason": reason})
        return request_obj

    @staticmethod
    @transaction.atomic
    def cancel_deletion_request(user: User, request_data: dict = None) -> None:
        """Cancel a pending deletion request. Logs an ACCOUNT_DELETE
        AuditLog entry (status: 'cancelled')."""
        # NOTE: unlike create_deletion_request above, select_for_update()
        # here IS correctly locking a row that must already exist (we're
        # cancelling a *pending* request) -- no equivalent fix needed here.
        request_obj = AccountDeletionRequest.objects.select_for_update().filter(
            user=user, completed=False, cancelled=False
        ).first()
        if not request_obj:
            raise ServiceLayerError("No pending deletion request found.")

        request_obj.cancelled = True
        request_obj.save(update_fields=['cancelled'])
        logger.info("Deletion request cancelled for user %s", user.email)
        _log_audit(user, AuditLog.Action.ACCOUNT_DELETE, request_data, {"status": "cancelled"})

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

        No request_data is available here (this runs outside any HTTP
        request cycle) -- _log_audit() handles request_data=None gracefully.
        """
        request_obj = AccountDeletionRequest.objects.select_for_update().get(pk=request_obj.pk)
        if request_obj.completed or request_obj.cancelled:
            return

        user = request_obj.user
        user_email = user.email  # capture before delete -- AuditLog.user
        # will be SET_NULL once the User row is gone (see models.py), so
        # the email needs to live in metadata to remain readable afterward.

        request_obj.complete()
        # FIX (missing audit trail): log BEFORE user.delete() while `user`
        # is still a valid FK target. AuditLog.user is on_delete=SET_NULL,
        # so this row survives the deletion with user=NULL but retains the
        # email in metadata -- the only way to have a durable record of
        # *which* account was deleted after it no longer exists to look up.
        _log_audit(user, AuditLog.Action.ACCOUNT_DELETE, None,
                   {"status": "completed", "email": user_email})
        user.delete()
        logger.info("Account for user %s has been permanently deleted.", user_email)


# ===================== Views =====================

class AccountDeletionRequestView(APIView):
    """ Create a deletion request for the authenticated user (7-day grace period)."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = AccountDeletionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        deletion_request = AccountDeletionService.create_deletion_request(user=request.user,
            reason=serializer.validated_data.get('reason', ''),
            confirm=serializer.validated_data['confirm'],
            request_data=request_data
        )

        return Response({'success': True,
            'message': 'Deletion request submitted. Your account will be deleted on {}.'.format(
                deletion_request.scheduled_for.strftime('%Y-%m-%d %H:%M:%S')
            ),'request_id': deletion_request.id,'scheduled_for': deletion_request.scheduled_for
        }, status=status.HTTP_201_CREATED)


class AccountDeletionCancelView(APIView):
    """Cancel a pending deletion request."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = AccountDeletionCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        AccountDeletionService.cancel_deletion_request(user=request.user, request_data=request_data)
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