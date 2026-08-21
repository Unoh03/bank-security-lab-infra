"""Shuffle Cloud entry point for fixed Rule 100110 automatic containment."""

from shuffle_sdk import AppBase

from autocontainment import dispatch_rule_100110


class AwsTopologySocRule100110AutoContainment(AppBase):
    __version__ = "1.0.0"
    app_name = "SOC R110 Isolator"

    def dispatch_rule_100110(self, github_token, input_data):
        return dispatch_rule_100110(github_token, input_data)


if __name__ == "__main__":
    AwsTopologySocRule100110AutoContainment.run()
