package oppopush

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	MaxTimeToLive = 3600 * 23    // 提前一小时过期，然后重新获取
)

type OppoToken struct {
	AccessToken string `json:"access_token"`
	CreateTime  int64  `json:"create_time"`
}

var tokenInstance *OppoToken

func init() {
	tokenInstance = &OppoToken{
		AccessToken: "",
		CreateTime:  0,
	}
}

//GetToken 获取AccessToken值
func GetToken(appKey, masterSecret string) (*OppoToken, error) {
	//nowMilliSecond := time.Now().UnixNano() / 1e6
	//if (nowMilliSecond-tokenInstance.CreateTime) < MaxTimeToLive*1000 && tokenInstance.AccessToken != "" {
	//	return tokenInstance, nil
	//}
	// 从缓存中获取，若缓存中不存在则重新获取
	if tokenCache != nil{
		ti, err := tokenCache.CacheToken(appKey, masterSecret)
		if err != nil{
			return tokenInstance, err
		}
		if ti != nil{ // 若获取到了token，则更新，否则使用原先的
			tokenInstance.AccessToken = ti.Token
			tokenInstance.CreateTime = ti.TokenCreateTime
		}
	} else {
		ot, err := GetTokenByRequest(appKey, masterSecret)
		if err != nil{
			return tokenInstance, err
		}
		if ot != nil{
			tokenInstance.AccessToken = ot.AccessToken
			tokenInstance.CreateTime = ot.CreateTime
		}
	}
	return tokenInstance, nil
}

func GetTokenByRequest(appKey, masterSecret string) (*OppoToken, error) {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	shaByte := sha256.Sum256([]byte(appKey + timestamp + masterSecret))
	sign := fmt.Sprintf("%x", shaByte)
	params := url.Values{}
	params.Add("app_key", appKey)
	params.Add("sign", sign)
	params.Add("timestamp", timestamp)
	resp, err := http.PostForm(PushHost+AuthURL, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result AuthSendResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}
	if result.Code != 0 {
		return nil, errors.New(result.Message)
	}
	return &OppoToken{
		AccessToken: result.Data.AuthToken,
		CreateTime: result.Data.CreateTime,
	}, nil
}
