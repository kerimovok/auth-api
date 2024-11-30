package utils

import "github.com/gofiber/fiber/v2"

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func SuccessResponse(c *fiber.Ctx, message string, data interface{}) error {
	return c.Status(fiber.StatusOK).JSON(Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func ErrorResponse(c *fiber.Ctx, status int, message string, err error) error {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	return c.Status(status).JSON(Response{
		Success: false,
		Message: message,
		Error:   errMsg,
	})
}
