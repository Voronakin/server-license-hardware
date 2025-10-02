package license

type Scope struct {
	ID          string
	Name        string
	Description string
}

var allScopes []Scope

func InitScopes(scopes []Scope) {
	allScopes = scopes
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
		for _, scope := range allScopes {
			if scope.ID == id {
				result = append(result, scope)
				break
			}
		}
	}

	return result
}
