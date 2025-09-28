package license

const (
	ScopeReportDayBalanceId                = "r_day_balance"
	ScopeNotificationAppointmentReminderId = "n_appoint_rem"
)

type Scope struct {
	ID          string
	Name        string
	Description string
}

var (
	scopeReportDayBalance = Scope{
		ID:          ScopeReportDayBalanceId,
		Name:        "Касса за день",
		Description: "Просмотр страницы с отображением списка изменений баланса за текущий день",
	}

	scopeNotificationAppointmentReminder = Scope{
		ID:          ScopeNotificationAppointmentReminderId,
		Name:        "Напоминания о приеме",
		Description: "Отправка уведомлений с напоминаниями о назначенных приемах",
	}

	AllScopes = []Scope{
		scopeReportDayBalance,
		scopeNotificationAppointmentReminder,
	}
)

func GetScopeByID(id string) (Scope, bool) {
	for _, scope := range AllScopes {
		if scope.ID == id {
			return scope, true
		}
	}
	return Scope{}, false
}

func GetScopeIds(scopes []Scope) []string {
	result := make([]string, len(scopes))
	for i, s := range scopes {
		result[i] = s.ID
	}

	return result
}

func GetScopesByIds(ids []string) []Scope {
	var result []Scope
	for _, id := range ids {
		scope, ok := GetScopeByID(id)
		if ok {
			result = append(result, scope)
		}
	}

	return result
}
