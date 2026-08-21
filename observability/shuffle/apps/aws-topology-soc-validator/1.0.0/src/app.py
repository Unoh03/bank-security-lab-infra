"""Shuffle Cloud entry point for the fixed SOC payload validator."""

from shuffle_sdk import AppBase

from validator import classify_dedupe_claim, validate_sanitized_alert


class AwsTopologySocValidator(AppBase):
    __version__ = "1.0.0"
    app_name = "AWS Topology SOC Validator"

    def validate_sanitized_alert(self, input_data):
        return validate_sanitized_alert(input_data)

    def classify_dedupe_claim(self, claim_result, expected_key):
        return classify_dedupe_claim(claim_result, expected_key)


if __name__ == "__main__":
    AwsTopologySocValidator.run()
