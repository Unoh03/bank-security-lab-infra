from pathlib import Path
import subprocess

DAILY_COMMON_BLOB = "f8d8932eee8137c84013d26e1d6c4c096cccae52"
FLEET_TEST_BLOB = "88695cdac1f1083c4a146ae6c0b055c26b39a211"


def assert_blob(path: Path, expected: str) -> None:
    actual = subprocess.check_output(
        ["git", "hash-object", str(path)], text=True
    ).strip()
    if actual != expected:
        raise SystemExit(
            f"{path} changed unexpectedly: {actual} != {expected}"
        )


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"expected one patch target in {path}, received {count}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


daily_common = Path("daily-common.ps1")
fleet_test = Path("tests/test-fleet-residue.ps1")
assert_blob(daily_common, DAILY_COMMON_BLOB)
assert_blob(fleet_test, FLEET_TEST_BLOB)

replace_once(
    daily_common,
    """                    $instanceIds = @(
                        $fleet.Instances |
                            ForEach-Object { @($_.InstanceIds) } |
                            Where-Object { $_ } |
                            ForEach-Object { [string]$_ } |
                            Sort-Object -Unique
                    )
""",
    """                    $instanceIds = @(
                        @(
                            foreach ($fleetInstance in @($fleet.Instances)) {
                                if ($null -eq $fleetInstance) {
                                    continue
                                }
                                if ($fleetInstance.PSObject.Properties.Name -notcontains 'InstanceIds') {
                                    continue
                                }
                                foreach ($rawInstanceId in @($fleetInstance.InstanceIds)) {
                                    $candidate = ([string]$rawInstanceId).Trim()
                                    if ($candidate) {
                                        $candidate
                                    }
                                }
                            }
                        ) | Sort-Object -Unique
                    )
""",
)

replace_once(
    fleet_test,
    """        $instanceIds = switch ($global:FleetResidueMockScenario) {
            'no-instance-ids' { @() }
            'mixed-notfound-running' {
""",
    """        $instanceIds = switch ($global:FleetResidueMockScenario) {
            'no-instance-ids' { @() }
            'blank-instance-ids' { @('', '   ', $null) }
            'mixed-notfound-running' {
""",
)

replace_once(
    fleet_test,
    """    $global:FleetResidueMockScenario = 'no-instance-ids'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'A deleting Fleet with no referenced instances must be inactive.'

    $global:FleetResidueMockScenario = 'access-denied'
""",
    """    $global:FleetResidueMockScenario = 'no-instance-ids'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'A deleting Fleet with no referenced instances must be inactive.'

    $global:FleetResidueMockScenario = 'blank-instance-ids'
    Assert-False `
        -Condition ([bool](Test-TaggedProjectRuntimeResourceActive `
            -Arn $arn -Profile 'test' -Region 'ap-northeast-2')) `
        -Message 'Blank or whitespace Fleet instance IDs must be ignored.'

    $global:FleetResidueMockScenario = 'access-denied'
""",
)
