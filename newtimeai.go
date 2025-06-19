package newtimeai

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	BaseURL = "https://open.gateway.newtimeai.com"
)

const (
	obtainTokenUrl        = "/gateway/genToken/obtainToken"               //生成token
	getDpptTokenUrl       = "/qdjk/fullExteriorInvoke/getDpptToken"       //获取登录验证码
	loginDpptUrl          = "/qdjk/fullExteriorInvoke/loginDppt"          //登录电票平台
	getFaceImgUrl         = "/qdjk/fullExteriorInvoke/getFaceImg"         //获取人脸二维码
	getFaceStateUrl       = "/qdjk/fullExteriorInvoke/getFaceState"       //获取人脸二维码状态
	queryFaceAuthStateUrl = "/qdjk/fullExteriorInvoke/queryFaceAuthState" //判断是否需要人脸识别
	createBlueTicketUrl   = "/qdjk/fullExteriorInvoke/blueTicket"         // 创建蓝票
)

var (
	ObtainTokenErr        = errors.New("获取token失败")
	GetDpptTokenErr       = errors.New("GetDpptToken 失败")
	LoginDpptErr          = errors.New("LoginDppt 失败")
	GetFaceImgErr         = errors.New("GetFaceImg 失败")
	QueryFaceAuthStateErr = errors.New("QueryFaceAuthState 失败")
	CreateBlueTicketErr   = errors.New("CreateBlueTicket 失败")
)

const tokenValidPeriod = 100 * 60 //官方是2个小时，这里改为100分钟，防止快到期的问题

type Map map[string]interface{}

type Client struct {
	secret        string    //secret
	key           string    //key
	validPeriod   int       //token 有效期
	token         string    //内存中的token
	tokenExpireAt time.Time //token 过期时间，超过该时间则重新获取
}

func NewClient(secret, key string) *Client {
	return &Client{
		secret:      secret,
		key:         key,
		validPeriod: tokenValidPeriod,
	}
}

type BaseResponse struct {
	Code string      `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

func (b *BaseResponse) isSuccess() bool {
	return b.Code == "200"
}

type obtainTokenResponse struct {
	Token string `json:"token"`
}

func (c *Client) checkTokenExpire() bool {
	if c.token == "" || time.Now().After(c.tokenExpireAt) { //token为空，或者当前时间大于token有效期则重新获取token
		return false
	}

	return true
}

// 获取请求头参数
func (c *Client) getHeader(reqPath string) Map {
	timestamp := getTime()

	urlSign := getUrlSign(timestamp, c.token, reqPath)

	return Map{
		"token":     c.token,
		"sign":      urlSign,
		"timestamp": timestamp,
		"url":       reqPath,
	}
}

// 获取接口sign
func getUrlSign(timestamp, token, urlPath string) string {
	params := Map{
		"timestamp": timestamp,
		"token":     token,
		"url":       urlPath,
	}
	return getSign(params)
}

// 获取token的sign
func getTokenSign(timestamp, key, secret string) string {
	params := Map{
		"key":       key,
		"secret":    secret,
		"timestamp": timestamp,
	}
	return getSign(params)
}

// 生成sign
func getSign(params Map) string {
	// 对key进行排序
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		v := obTstr(params[k])
		if v != "" {
			buf.WriteString(k)
			buf.WriteString("=")
			buf.WriteString(v)
			buf.WriteString("&")
		}
	}

	str := ""
	if buf.Len() > 0 {
		str = buf.String()[:buf.Len()-1]
	}

	// 进行MD5加密并转为大写
	hash := md5.Sum([]byte(str))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// 获取时间戳
func getTime() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 10)
}

// 转字符串
func obTstr(ob interface{}) string {
	switch v := ob.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// HTTP GET请求
func (c *Client) httpGet(requestUrl string, request interface{}, headers Map) (*BaseResponse, error) {
	if !c.checkTokenExpire() {
		if err := c.obtainToken(); err != nil {
			return nil, err
		}
	}

	var params Map
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(payload, &params); err != nil {
		return nil, err
	}

	// 构建URL参数
	values := url.Values{}
	for k, v := range params {
		values.Add(k, obTstr(v))
	}

	// 如果有参数，添加到URL中
	if len(values) > 0 {
		if strings.Contains(requestUrl, "?") {
			requestUrl += "&" + values.Encode()
		} else {
			requestUrl += "?" + values.Encode()
		}
	}

	req, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	for k, v := range headers {
		req.Header.Set(k, obTstr(v))
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response *BaseResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response, nil
}

// HTTP POST请求
func (c *Client) httpPost(requestUrl string, request interface{}, headers Map) (*BaseResponse, error) {
	if !c.checkTokenExpire() {
		if err := c.obtainToken(); err != nil {
			return nil, err
		}
	}

	var params Map
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(payload, &params); err != nil {
		return nil, err
	}

	// 构建表单数据
	values := url.Values{}
	for k, v := range params {
		// 处理fyxm数组
		if k == "fyxm" {
			if items, ok := v.([]Map); ok {
				for i, item := range items {
					for fk, fv := range item {
						key := fmt.Sprintf("fyxm[%d][%s]", i, fk)
						values.Add(key, obTstr(fv))
					}
				}
			}
			continue
		}
		values.Add(k, obTstr(v))
	}

	req, err := http.NewRequest("POST", requestUrl, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, obTstr(v))
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response *BaseResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response, nil
}

// 生成Token
func (c *Client) obtainToken() error {
	timestamp := getTime()
	tokenSign := getTokenSign(timestamp, c.key, c.secret)

	requestUrl := BaseURL + obtainTokenUrl
	params := Map{
		"key":       c.key,
		"timestamp": timestamp,
		"sign":      tokenSign,
	}

	response, err := c.httpGet(requestUrl, params, Map{})
	if err != nil {
		return err
	}

	if !response.isSuccess() {
		return ObtainTokenErr
	}

	payload, err := json.Marshal(response.Data)
	if err != nil {
		return err
	}

	var obtainTokenRes obtainTokenResponse
	if err = json.Unmarshal(payload, &obtainTokenRes); err != nil {
		return err
	}

	c.token = obtainTokenRes.Token
	c.tokenExpireAt = time.Now().Add(tokenValidPeriod * time.Second)

	return nil
}

type GetDpptTokenRequest struct {
	Nsrsbh string `json:"nsrsbh"`
	Sms    string `json:"sms"`
	Ewmlx  string `json:"ewmlx"`
	Ewmid  string `json:"ewmid"`
}

type GetDpptTokenResponse struct {
	Ewmid  string `json:"ewmid"`
	Qrcode string `json:"qrcode"`
}

func (c *Client) GetDpptToken(req GetDpptTokenRequest) (*GetDpptTokenResponse, error) {
	reqUrl := BaseURL + getDpptTokenUrl
	response, err := c.httpPost(reqUrl, req, c.getHeader(getDpptTokenUrl))
	if err != nil {
		return nil, err
	}

	if !response.isSuccess() {
		return nil, GetDpptTokenErr
	}
	payload, err := json.Marshal(response.Data)
	if err != nil {
		return nil, err
	}

	var getDpptTokenRes *GetDpptTokenResponse
	if err = json.Unmarshal(payload, &getDpptTokenRes); err != nil {
		return nil, err
	}

	return getDpptTokenRes, nil
}

type LoginDpptRequest struct {
	Nsrsbh   string `json:"nsrsbh"`
	Username string `json:"username"`
	Password string `json:"password"`
	Sms      string `json:"sms"`
	Ewmlx    string `json:"ewmlx"`
	Ewmid    string `json:"ewmid"`
}

type LoginDpptResponse struct {
	Ewmid  string `json:"ewmid"`
	Qrcode string `json:"qrcode"`
}

func (c *Client) LoginDppt(req LoginDpptRequest) (*LoginDpptResponse, error) {
	reqUrl := BaseURL + loginDpptUrl
	response, err := c.httpPost(reqUrl, req, c.getHeader(loginDpptUrl))
	if err != nil {
		return nil, err
	}

	if !response.isSuccess() {
		return nil, LoginDpptErr
	}
	payload, err := json.Marshal(response.Data)
	if err != nil {
		return nil, err
	}

	var LoginDpptRes *LoginDpptResponse
	if err = json.Unmarshal(payload, &LoginDpptRes); err != nil {
		return nil, err
	}

	return LoginDpptRes, nil
}

type GetFaceImgRequest struct {
	Nsrsbh   string `json:"nsrsbh"`
	Username string `json:"username"`
	ImgType  string `json:"imgType"`
}

type GetFaceImgResponse struct {
	Rzid   string `json:"rzid"`
	Nsrsbh string `json:"nsrsbh"`
	Ewm    string `json:"ewm"`
	Slzt   string `json:"slzt"`
	Emwly  string `json:"emwly"`
}

func (c *Client) GetFaceImg(req GetFaceImgRequest) (*GetFaceImgResponse, error) {
	reqUrl := BaseURL + getFaceImgUrl
	response, err := c.httpGet(reqUrl, req, c.getHeader(getFaceImgUrl))
	if err != nil {
		return nil, err
	}

	if !response.isSuccess() {
		return nil, GetFaceImgErr
	}
	payload, err := json.Marshal(response.Data)
	if err != nil {
		return nil, err
	}

	var getFaceImgRes *GetFaceImgResponse
	if err = json.Unmarshal(payload, &getFaceImgRes); err != nil {
		return nil, err
	}

	return getFaceImgRes, nil
}

type GetFaceStateRequest struct {
	Nsrsbh   string `json:"nsrsbh"`
	Username string `json:"username"`
	Type     string `json:"type"`
}

type GetFaceStateResponse struct {
	Rzid   string `json:"rzid"`
	Nsrsbh string `json:"nsrsbh"`
	Ewm    string `json:"ewm"`
	Slzt   string `json:"slzt"` //受理状态，1-未认证，2-成功，3-二维码过期
}

func (c *Client) GetFaceState(req GetFaceStateRequest) (*GetFaceStateResponse, error) {
	reqUrl := BaseURL + getFaceStateUrl
	response, err := c.httpGet(reqUrl, req, c.getHeader(getFaceStateUrl))
	if err != nil {
		return nil, err
	}

	if !response.isSuccess() {
		return nil, GetDpptTokenErr
	}
	payload, err := json.Marshal(response.Data)
	if err != nil {
		return nil, err
	}

	var getFaceStateRes *GetFaceStateResponse
	if err = json.Unmarshal(payload, &getFaceStateRes); err != nil {
		return nil, err
	}

	return getFaceStateRes, nil
}

type QueryFaceAuthStateRequest struct {
	Nsrsbh   string `json:"nsrsbh"`
	Username string `json:"username"`
}

type QueryFaceAuthStateResponse struct {
	Yjjb        string `json:"Yjjb"`
	Sxlb        string `json:"Sxlb"`
	Sfsl        string `json:"Sfsl"` // 为N不需要人脸，为Y需要人脸
	ItsScanFlag string `json:"ItsScanFlag"`
}

func (c *Client) QueryFaceAuthState(req QueryFaceAuthStateRequest) (*QueryFaceAuthStateResponse, error) {
	reqUrl := BaseURL + queryFaceAuthStateUrl
	response, err := c.httpPost(reqUrl, req, c.getHeader(queryFaceAuthStateUrl))
	if err != nil {
		return nil, err
	}

	if !response.isSuccess() {
		return nil, QueryFaceAuthStateErr
	}

	//这里返回的是字符串，需要用base64解密
	data, ok := response.Data.(string)
	if !ok {
		return nil, QueryFaceAuthStateErr
	}

	payload, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, QueryFaceAuthStateErr
	}

	var queryFaceAuthStateRes *QueryFaceAuthStateResponse
	if err = json.Unmarshal(payload, &queryFaceAuthStateRes); err != nil {
		return nil, err
	}

	return queryFaceAuthStateRes, nil
}

type fyxm struct {
	Fphxz   string `json:"fphxz"`   //发票行性质，0-正常行，1-折扣行，2-被折扣行
	Spmc    string `json:"spmc"`    //商品名称
	Ggxh    string `json:"ggxh"`    //商品规格
	Dw      string `json:"dw"`      //单位
	Spsl    int64  `json:"spsl"`    //商品数量
	Dj      int64  `json:"dj"`      //单价
	Je      int64  `json:"je"`      //金额
	Sl      string `json:"sl"`      //税率
	Se      int64  `json:"se"`      //税额
	Hsbz    string `json:"hsbz"`    //含税标志，0-不含税，1-含税
	Spbm    string `json:"spbm"`    //商品编码
	Yhzcbs  string `json:"yhzcbs"`  //优惠赠策标识，0-未使用，1-使用
	Lslbs   string `json:"lslbs"`   //零税率标识，0-正常税率，1-出口免税，2-不征增值税，3-普通零汇率
	Zzstsgl string `json:"zzstsgl"` //增值税特殊管理
}

type CreateBlueTicketReq struct {
	Fpqqlsh  string `json:"fpqqlsh"`  //发票请求流水号,唯一值，如若不传自行生成
	Username string `json:"username"` //用户电票平台账号
	Fplxdm   string `json:"fplxdm"`   //发票类型，81-数电发票（增值税专用发票），82-数电发票（普通发票）
	TdyslxDm string `json:"tdyslxDm"` //特殊票种
	Kplx     string `json:"kplx"`     //0-整数发票
	Qdbz     string `json:"qdbz"`     //清单标志
	Xhdwsbh  string `json:"xhdwsbh"`  //销方识别号
	Xhdwmc   string `json:"xhdwmc"`   //销方名称
	Xhdwdzdh string `json:"xhdwdzdh"` //销方地址
	Xhdwyhzh string `json:"xhdwyhzh"` //销方银行账户
	Ghdwsbh  string `json:"ghdwsbh"`  //购方税号
	Ghdwmc   string `json:"ghdwmc"`   //购方名称
	Ghdwdzdh string `json:"ghdwdzdh"` //购方地址
	Ghdwyhzh string `json:"ghdwyhzh"` //购方银行账号
	Zsfs     string `json:"zsfs"`     //征收方式，0-普通征税，1-差额征税全额开具，2-差额征税差额开具
	Fxm      []fyxm `json:"fxm"`      //发票项目
	Hjje     string `json:"hjje"`     //合计金额
	Hjse     string `json:"hjse"`     //合计税额
	Jshj     string `json:"jshj"`     //价税合计
	Kce      string `json:"kce"`      //扣除额
	Kpr      string `json:"kpr"`      //开票人
	Skr      string `json:"skr"`      //收款人
	Fhr      string `json:"fhr"`      //复核人
}

type CreateBlueTicketResponse struct {
	Fphm         string `json:"Fphm"`         //发票请求流水号
	Kprq         string `json:"Kprq"`         //发票日期
	Gmfyx        string `json:"gmfyx"`        //购买方邮箱
	GmfSsjswjgdm string `json:"gmfSsjswjgdm"` //购买方税局机关代码
	Ewm          string `json:"ewm"`          //二维码
	Zzfpdm       string `json:"zzfpdm"`       //纸质发票代码
	Zzfphm       string `json:"zzfphm"`       //纸质发票号码
}

func (c *Client) CreateBlueTicket(req CreateBlueTicketReq) (*CreateBlueTicketResponse, error) {
	reqUrl := BaseURL + createBlueTicketUrl
	response, err := c.httpPost(reqUrl, req, c.getHeader(createBlueTicketUrl))
	if err != nil {
		return nil, err
	}

	if !response.isSuccess() {
		return nil, CreateBlueTicketErr
	}

	payload, err := json.Marshal(response.Data)
	if err != nil {
		return nil, err
	}

	var createBlueTicketRes *CreateBlueTicketResponse
	if err = json.Unmarshal(payload, &createBlueTicketRes); err != nil {
		return nil, err
	}

	return createBlueTicketRes, nil
}
