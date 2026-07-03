"""
Integration-style tests for MCP tool functions.
Graph/Azure calls are mocked — no live credentials needed.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.risk.thresholds import RiskLevel


class TestRemediateRecommendation:
    @pytest.mark.asyncio
    async def test_low_risk_executes(self):
        """LOW risk remediation should auto-execute without Teams card."""
        with (
            patch("src.tools.defender_cloud.score_action") as mock_score,
            patch("src.tools.defender_cloud.get_azure_token", new_callable=AsyncMock) as mock_token,
            patch("httpx.AsyncClient") as mock_http,
        ):
            from src.risk.thresholds import RiskScore
            mock_score.return_value = RiskScore(
                score=10, level=RiskLevel.LOW,
                reasoning="Low risk", factors={}
            )
            mock_token.return_value = "fake-token"
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_http.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_resp)

            from src.tools.defender_cloud import remediate_recommendation
            result = await remediate_recommendation(
                assessment_name="test-assessment",
                resource_id="/subscriptions/test/resourceGroups/rg/providers/test",
                description="Enable disk encryption",
                affected_count=1,
                total_count=10,
            )

        assert result["outcome"] == "executed"
        assert result["risk_level"] == "LOW"

    @pytest.mark.asyncio
    async def test_medium_risk_sends_teams_card(self):
        """MEDIUM risk should send Teams approval card, not execute."""
        with (
            patch("src.tools.defender_cloud.score_action") as mock_score,
            patch("src.tools.defender_cloud.send_escalation_card", new_callable=AsyncMock) as mock_teams,
        ):
            from src.risk.thresholds import RiskScore
            mock_score.return_value = RiskScore(
                score=50, level=RiskLevel.MEDIUM,
                reasoning="Medium risk", factors={}
            )
            mock_teams.return_value = {"sent": True}

            from src.tools.defender_cloud import remediate_recommendation
            result = await remediate_recommendation(
                assessment_name="test",
                resource_id="/subscriptions/test/rg/resource",
                description="Update network security group",
                affected_count=50,
                total_count=100,
            )

        assert result["outcome"] == "pending_approval"
        mock_teams.assert_called_once()
        call_kwargs = mock_teams.call_args[1]
        assert call_kwargs["require_approval"] is True

    @pytest.mark.asyncio
    async def test_high_risk_escalates_only(self):
        """HIGH risk should escalate and never execute."""
        with (
            patch("src.tools.defender_cloud.score_action") as mock_score,
            patch("src.tools.defender_cloud.send_escalation_card", new_callable=AsyncMock) as mock_teams,
        ):
            from src.risk.thresholds import RiskScore
            mock_score.return_value = RiskScore(
                score=85, level=RiskLevel.HIGH,
                reasoning="High risk", factors={}
            )
            mock_teams.return_value = {"sent": True}

            from src.tools.defender_cloud import remediate_recommendation
            result = await remediate_recommendation(
                assessment_name="test",
                resource_id="/subscriptions/test/rg/resource",
                description="Delete all public IP addresses",
                affected_count=100,
                total_count=100,
            )

        assert result["outcome"] == "escalated"
        mock_teams.assert_called_once()
        call_kwargs = mock_teams.call_args[1]
        assert call_kwargs["require_approval"] is False


class TestCreateActionPlan:
    @pytest.mark.asyncio
    async def test_action_plan_structure(self):
        """Action plan should include all required fields."""
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

        # Import via server tool function
        from src.server import create_action_plan
        result = await create_action_plan(
            finding_title="MFA not enforced for admins",
            finding_description="3 admin accounts without MFA registered",
            severity="High",
            affected_assets=["admin@company.com", "it@company.com", "ceo@company.com"],
            recommended_steps=[
                "Identify all admin accounts via get_mfa_status",
                "Enable MFA enforcement via Conditional Access policy",
                "Verify compliance within 48 hours",
            ],
            business_impact="Credential compromise of admin accounts would grant full tenant access",
            deadline_days=7,
        )

        assert "plan_id" in result
        assert result["severity"] == "High"
        assert result["asset_count"] == 3
        assert len(result["steps"]) == 3
        assert result["steps"][0]["step"] == 1
        assert "formatted_summary" in result
        assert "High" in result["formatted_summary"]


class TestAssessRisk:
    @pytest.mark.asyncio
    async def test_assess_risk_returns_all_fields(self):
        from src.server import assess_risk
        result = await assess_risk(
            action_type="block_user",
            description="Block compromised user account",
            affected_resource="user@company.com",
            affected_count=1,
            total_count=500,
            is_reversible=True,
            service_critical=False,
            touches_pii=True,
            recently_changed=False,
            severity="High",
        )

        assert "score" in result
        assert "level" in result
        assert "reasoning" in result
        assert "factors" in result
        assert isinstance(result["auto_execute"], bool)
        assert isinstance(result["requires_approval"], bool)
        assert isinstance(result["escalate_only"], bool)
        # Only one decision path should be true
        decisions = [result["auto_execute"], result["requires_approval"], result["escalate_only"]]
        assert sum(decisions) == 1
