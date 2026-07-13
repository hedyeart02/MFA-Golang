package audit

import "time"

// LogEventRequest is the request body for creating an audit log entry.
type LogEventRequest struct {
	UserID        string `json:"user_id"`
	EventType     string `json:"event_type" binding:"required"`
	Action        string `json:"action" binding:"required"`
	IPAddress     string `json:"ip_address"`
	UserAgent     string `json:"user_agent"`
	CorrelationID string `json:"correlation_id"`
	Details       string `json:"details"`
	Severity      string `json:"severity"`
}

// LogQueryParams holds query parameters for filtering audit logs.
type LogQueryParams struct {
	UserID    string    `form:"user_id"`
	EventType string   `form:"event_type"`
	Severity  string   `form:"severity"`
	StartDate time.Time `form:"start_date" time_format:"2006-01-02T15:04:05Z07:00"`
	EndDate   time.Time `form:"end_date" time_format:"2006-01-02T15:04:05Z07:00"`
	Page      int       `form:"page,default=1"`
	PageSize  int       `form:"page_size,default=20"`
}

// LogEventResponse is the response after creating an audit log entry.
type LogEventResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// EventTypeResponse lists distinct event types.
type EventTypeResponse struct {
	EventTypes []string `json:"event_types"`
}
