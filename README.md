# Chronos-V3-and-the-Architecture-of-Conjunctive-Transparency

## Getting Started

### Environment Configuration

Before running the application using Docker Compose, create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Ensure that `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` are defined in your `.env` file with secure values. Docker Compose requires these variables and will fail to initialize if they are missing.
