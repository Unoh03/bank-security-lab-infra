"""Shuffle Cloud entry point for the fixed GitHub containment dispatcher."""

from shuffle_sdk import AppBase

from dispatcher import dispatch_containment


class AwsTopologySocGithubDispatcher(AppBase):
    __version__ = "1.0.0"
    app_name = "AWS Topology SOC GitHub Dispatcher"

    def dispatch_containment(
        self, github_token, take_id, scenario_id, rule_id, alert_body_sha256
    ):
        return dispatch_containment(
            github_token,
            take_id,
            scenario_id,
            rule_id,
            alert_body_sha256,
        )


if __name__ == "__main__":
    AwsTopologySocGithubDispatcher.run()
