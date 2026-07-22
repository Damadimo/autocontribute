import pytest

from autocontribute.exceptions import ConfigurationError
from autocontribute.github_origin import canonical_api_origin, git_push_url, web_origin_for_api


def test_github_com_and_ghes_origins_derive_credential_safe_push_urls() -> None:
    assert canonical_api_origin("https://api.github.com/") == "https://api.github.com"
    assert web_origin_for_api("https://api.github.com") == "https://github.com"
    assert (
        git_push_url("https://api.github.com", "octocat/project")
        == "https://github.com/octocat/project.git"
    )

    assert canonical_api_origin("https://git.example.com/api/v3") == "https://git.example.com"
    assert web_origin_for_api("https://git.example.com/api/v3") == "https://git.example.com"
    assert (
        git_push_url("https://git.example.com/api/v3", "octocat/project")
        == "https://git.example.com/octocat/project.git"
    )
    assert (
        web_origin_for_api("https://git.example.com:8443/api/v3") == "https://git.example.com:8443"
    )


@pytest.mark.parametrize(
    "api_url",
    [
        "http://git.example.com/api/v3",
        "https://token@git.example.com/api/v3",
        "https://git.example.com/api/v3?redirect=github.com",
        "https://git.example.com/api/v3#fragment",
        "https:///api/v3",
    ],
)
def test_unsafe_api_origins_are_rejected(api_url: str) -> None:
    with pytest.raises(ConfigurationError):
        canonical_api_origin(api_url)


@pytest.mark.parametrize("repository", ["project", "owner/project/extra", "../project"])
def test_push_url_requires_one_canonical_repository_name(repository: str) -> None:
    with pytest.raises(ConfigurationError, match="owner/name"):
        git_push_url("https://api.github.com", repository)
