package oppopush

var tokenCache TokenCache

type TokenCache interface {
	// 设置成功后 删除全局锁
	Set(t *TokenInfo) error
	// 获取token信息，若为空则返回 nil。若为空则需要重新获取，需要同步保证一致
	Get() (*TokenInfo, error)
}

func InitTokenCache(t TokenCache) {
	tokenCache = t
}

type TokenInfo struct {
	Token string
	TokenCreateTime int64
	KeyExpire int64
}