package contentdiscovery

// DefaultWordlist is intentionally small and curated for authorized assessment.
var DefaultWordlist = []string{
	"/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/humans.txt", "/security.txt",
	"/admin", "/admin/", "/administrator", "/login", "/signin", "/logout", "/register", "/signup", "/user", "/users", "/account", "/profile", "/dashboard", "/console", "/manage", "/settings",
	"/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/", "/api/health", "/api/status", "/api/docs", "/api/swagger.json", "/swagger.json", "/openapi.json", "/graphql", "/graphiql", "/health", "/healthz", "/ready", "/readiness", "/live", "/status",
	"/docs", "/documentation", "/redoc", "/swagger", "/swagger-ui", "/swagger-ui/", "/help", "/support", "/blog", "/news", "/about", "/contact",
	"/backup", "/backups", "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql", "/dump.sql", "/config", "/config.json", "/config.yml", "/config.yaml", "/settings.json", "/application.properties", "/web.config", "/server-status",
	"/upload", "/uploads", "/files", "/download", "/downloads", "/media", "/static", "/assets", "/images", "/scripts", "/js", "/css", "/public", "/tmp", "/temp", "/logs", "/debug", "/trace", "/metrics", "/actuator", "/actuator/health", "/actuator/env",
	"/.dockerignore", "/Dockerfile", "/docker-compose.yml", "/package.json", "/composer.json", "/Gemfile", "/.DS_Store", "/.svn/entries", "/.hg/branch", "/.idea/", "/.vscode/",
}
