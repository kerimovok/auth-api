package utils

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

func GetUserIP(c *fiber.Ctx) string {
	// Check CF-Connecting-IP header first
	if ip := c.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}

	// Then check X-Forwarded-For
	if ip := c.Get("X-Forwarded-For"); ip != "" {
		// Take the first IP if multiple are present (client's original IP)
		if idx := strings.Index(ip, ","); idx != -1 {
			return strings.TrimSpace(ip[:idx])
		}
		return strings.TrimSpace(ip)
	}

	// Then check X-Real-IP
	if ip := c.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	// Finally fall back to RemoteAddr
	ip := c.IP()
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}
	return strings.TrimSpace(ip)
}
