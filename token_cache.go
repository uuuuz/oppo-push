package oppopush

type TokenCache interface {
	// 获取token信息，若为空则获取新的token
	CacheToken(appKey, masterSecret string) (*TokenInfo, error)
	// 清空缓存token，
	ClearToken() error
}

type TokenInfo struct {
	Token string `json:"token"`
	TokenCreateTime int64 `json:"token_create_time"`
	KeyExpire int64 `json:"key_expire"`
}