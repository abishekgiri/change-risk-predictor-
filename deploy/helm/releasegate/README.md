# ReleaseGate Helm Chart

## Install

```bash
helm install releasegate ./deploy/helm/releasegate \
  --set image.repository=ghcr.io/your-org/releasegate \
  --set image.tag=latest
```

## Upgrade

```bash
helm upgrade releasegate ./deploy/helm/releasegate
```

## Key values

- `image.repository` / `image.tag` - container image
- `env` - non-secret app configuration
- `secretEnv` - secret app configuration
- `ingress.enabled` - optional ingress exposure

## Example with ingress

```bash
helm install releasegate ./deploy/helm/releasegate \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=releasegate.example.com
```
