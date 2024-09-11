from fixtures.metrics import parse_metrics
from fixtures.neon_fixtures import NeonEnvBuilder, NeonProxy


def test_build_info_metric(neon_shared_env: NeonEnv, link_proxy: NeonProxy):
    env = neon_shared_env

    parsed_metrics = {}

    parsed_metrics["pageserver"] = parse_metrics(env.pageserver.http_client().get_metrics_str())
    parsed_metrics["safekeeper"] = parse_metrics(env.safekeepers[0].http_client().get_metrics_str())
    parsed_metrics["proxy"] = parse_metrics(link_proxy.get_metrics())

    for _component, metrics in parsed_metrics.items():
        sample = metrics.query_one("libmetrics_build_info")

        assert "revision" in sample.labels
        assert len(sample.labels["revision"]) > 0

        assert "build_tag" in sample.labels
        assert len(sample.labels["build_tag"]) > 0
