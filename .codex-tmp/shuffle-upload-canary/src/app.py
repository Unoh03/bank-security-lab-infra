"""Minimal disposable Shuffle Cloud upload canary."""

from shuffle_sdk import AppBase

from validator import classify_dedupe_claim, validate_sanitized_alert


class AwsTopologyValidatorModuleCanary(AppBase):
    __version__ = "0.0.3"
    app_name = "SOC Validator Module Canary"

    def validate_sanitized_alert(self, input_data):
        return validate_sanitized_alert(input_data)

    def classify_dedupe_claim(self, claim_result, expected_key):
        return classify_dedupe_claim(claim_result, expected_key)


if __name__ == "__main__":
    AwsTopologyValidatorModuleCanary.run()
