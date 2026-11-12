"""Centralized secret-provider abstractions and OpenBao readiness interfaces."""

from vforge.secrets.provider import (
    DatabaseCredentials,
    DockerSecretProvider,
    FutureExternalSecretProvider,
    LocalDevelopmentProvider,
    OpenBaoConfig,
    OpenBaoProvider,
    SecretLease,
    SecretProvider,
    SecretProviderNotConfiguredError,
    SecretResolutionError,
    build_secret_provider,
)

__all__ = [
    "DatabaseCredentials",
    "DockerSecretProvider",
    "FutureExternalSecretProvider",
    "LocalDevelopmentProvider",
    "OpenBaoConfig",
    "OpenBaoProvider",
    "SecretLease",
    "SecretProvider",
    "SecretProviderNotConfiguredError",
    "SecretResolutionError",
    "build_secret_provider",
]
