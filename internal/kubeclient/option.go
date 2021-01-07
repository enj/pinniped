package kubeclient

import restclient "k8s.io/client-go/rest"

type Option func(*clientConfig)

type clientConfig struct {
	config      *restclient.Config
	middlewares []Middleware
}

func WithConfig(config *restclient.Config) Option {
	return func(c *clientConfig) {
		c.config = config
	}
}

func WithMiddleware(middleware Middleware) Option {
	return func(c *clientConfig) {
		c.middlewares = append(c.middlewares, middleware)
	}
}
