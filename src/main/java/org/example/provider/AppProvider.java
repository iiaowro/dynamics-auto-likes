package org.example.provider;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.lang.Console;
import cn.hutool.extra.spring.SpringUtil;
import cn.hutool.http.HttpRequest;
import cn.hutool.json.JSON;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.ByteBuffer;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Component
public class AppProvider {

    private static RestTemplate restTemplate = new RestTemplate();

    // 申请captcha验证码
    public static final String LOGIN_CAPTCHA_URL = "https://passport.bilibili.com/x/passport-login/captcha?source=main_web";

    //  手动验证器
    public static final String LOGIN_CAPTCHA_VALIDATOR_URL = "https://kuresaru.github.io/geetest-validator/";

    // 获取公钥&盐(web端)
    public static final String LOGIN_WEB_KEY_URL = "https://passport.bilibili.com/x/passport-login/web/key";

    // 登录操作
    public static final String LOGIN_WEB_URL = "https://passport.bilibili.com/x/passport-login/web/login";

    // 获取国际冠字码
    public static final String LOGIN_WEB_CPUNTRY_URL = "https://passport.bilibili.com/web/generic/country/list";

    // 发送验证码
    public static final String LOGIN_WEB_SEND_SMS_URL = "https://passport.bilibili.com/x/passport-login/web/sms/send";

    // 验证码登录
    public static final String LOGIN_WEB_SMS_URL = "https://passport.bilibili.com/x/passport-login/web/login/sms";


    // qrcode生成
    public static final String LOGIN_WEB_QRCODE_GENERATE_URL = "https://passport.bilibili.com/x/passport-login/web/qrcode/generate";
    // qrcode 登录
    public static final String LOGIN_WEB_QRCODE_URL = "https://passport.bilibili.com/x/passport-login/web/qrcode/poll?qrcode_key=%s";


    // 用户登录后的cookie
    @Value("${app.localCookie}")
    public String LOCAL_COOKIE;
    // 用户登录后的refresh token   用于重置cookie
    @Value("${app.refreshToken}")
    public String LOCAL_REFRESH_TOKEN;

    // 用户登录后的refresh token   用于重置cookie
    @Value("${app.username}")
    public String LOCAL_USERNAME;
    // 用户登录后的refresh token   用于重置cookie
    @Value("${app.password}")
    public String LOCAL_PASSWORD;

    // 获取动态列表
    public static final String WEB_DYNAMIC_URL = "https://api.bilibili.com/x/polymer/web-dynamic/v1/feed/all?timezone_offset=-480&type=all&platform=web&page=1&features=itemOpusStyle,listOnlyfans,opusBigCover,onlyfansVote&web_location=333.1365";
    // 点赞
    public static final String WEB_THUMB_URL = "https://api.bilibili.com/x/dynamic/feed/dyn/thumb?csrf=%s";

    // 检查cookie状态
    public static final String WEB_COOKIE_INFO_URL = "https://passport.bilibili.com/x/passport-login/web/cookie/info";

    // cookie 加密公钥
    public static final String WEB_COOKIE_REFRESH_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLgd2OAkcGVtoE3ThUREbio0Eg Uc/prcajMKXvkCKFCWhJYJcLkcM2DKKcSeFpD/j6Boy538YXnR6VhcuUJOhH2x71 nzPjfdTcqMz7djHum0qSZA0AyCBDABUqCrfNgCiJ00Ra7GmRj+YCK1NJEuewlb40 JNrRuoEUXpabUzGB8QIDAQAB";


    // 获取refresh_csrf
    public static final String WEB_CSRF_URL = "https://www.bilibili.com/correspond/1/%s";


    // 刷新cookie
    public static final String WEB_COOKIE_REFRESH_URL = "https://passport.bilibili.com/x/passport-login/web/cookie/refresh";


    // 确认刷新cookie（删除旧cookie）
    public static final String WEB_COOKIE_CONFIRM_REFRESH_URL = "https://passport.bilibili.com/x/passport-login/web/confirm/refresh";


    public void loginPwdHandle() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        ResponseEntity<String> forEntity = restTemplate.getForEntity(LOGIN_CAPTCHA_URL, String.class);
        String token = "";
        String challenge = "";
        String validate = "";
        String seccode = "";
        if (forEntity.getStatusCodeValue() == 200) {
            JSONObject jsonObject = JSONUtil.parseObj(forEntity.getBody());
            Console.log("1. 成功申请captcha验证码：");
            Console.log("challenge = {}", jsonObject.getByPath("data.geetest.challenge").toString());
            challenge = jsonObject.getByPath("data.geetest.challenge").toString();
            Console.log("gt = {}", jsonObject.getByPath("data.geetest.gt").toString());
            Console.log("请打开网页：{}，手动进行验证，并按照下面提示输入返回结果（按回车键结束输入）", LOGIN_CAPTCHA_VALIDATOR_URL);
            Console.log("请输入 validate：");
            validate = Console.input();
            Console.log("请输入 seccode：");
            seccode = Console.input();
            Console.log("validate = {}, seccode = {}", validate, seccode);
            token = jsonObject.getByPath("data.token").toString();
        }
        String username = "";
        String password = "";

//
//        Console.log("请输入 用户名：");
//        username = Console.input();
//        Console.log("请输入 密码：");
//        password = Console.input();
        Console.log("请输入 用户名：");
        username = LOCAL_USERNAME;
        Console.log("请输入 密码：");


        password = Arrays.toString(Base64.decode(LOCAL_PASSWORD));
        password = encodePwd(username, password);
        // login
        MultiValueMap<String, String> paramMap = new LinkedMultiValueMap<String, String>(7);
        paramMap.add("username", username);
        paramMap.add("password", password);
        paramMap.add("keep", "0");
        paramMap.add("token", token);
        paramMap.add("challenge", challenge);
        paramMap.add("validate", validate);
        paramMap.add("seccode", seccode);
        paramMap.add("source", "main_web");
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        httpHeaders.set("APP-KEY", "android64");
        httpHeaders.set("Buvid", "andro16WEG1AEW1G98B181D6B18S9Bid641");
        httpHeaders.set("authority", "android641");
        httpHeaders.set("cookie", "buvid3=5A8BEDB0-E7CC-E57C-26AB-1F9E954E3F5813664infoc; b_nut=1699404813; i-wanna-go-back=-1; b_ut=7; _uuid=C1EBB5F1-10E10F-8F78-10FA1-64F10245161010516833infoc; buvid4=614DAFB6-9951-0590-DD1D-C915E355D9FC14414-023110808-AsDi2%2Fv1r4A7TyrTiKSXhQ%3D%3D; home_feed_column=5; fingerprint=5293d81feba8c0ab14c1d4cd4305a91e; buvid_fp_plain=undefined; browser_resolution=1581-950; bp_video_offset_2644599=889688761538969671; bili_ticket=eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDYyNTExODgsImlhdCI6MTcwNTk5MTkyOCwicGx0IjotMX0.sJzhB0WdqcQoQmd3udSHgsAuW4WgPN3zOMmOaPP6mdo; bili_ticket_expires=1706251128; sid=5wlmrnfi; enable_web_push=DISABLE; header_theme_version=CLOSE; b_lsid=3223F47F_18D353DBB41; bsource=search_bing; buvid_fp=5293d81feba8c0ab14c1d4cd4305a91e");
        httpHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
        httpHeaders.set("env", "prod");
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<MultiValueMap<String, String>>(paramMap, httpHeaders);
        ResponseEntity<String> exchange =
                restTemplate.exchange(LOGIN_WEB_URL, HttpMethod.POST, requestEntity, String.class);
        LOCAL_COOKIE = exchange.getHeaders().get("Set-Cookie").toString();
        LOCAL_REFRESH_TOKEN = JSONUtil.parse(exchange.getBody().toString()).getByPath("data.refresh_token").toString();


        Console.log("login请求结果:", exchange.getBody());

        Console.log("登录成功！ O(∩_∩)O");
        Console.log("LOCAL_COOKIE = {}", LOCAL_COOKIE.replace("[", "").replace("]", ""));
        Console.log("LOCAL_REFRESH_TOKEN = {}", LOCAL_REFRESH_TOKEN);
    }


    public void loginSMSHandle() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        ResponseEntity<String> forEntity = restTemplate.getForEntity(LOGIN_CAPTCHA_URL, String.class);
        String token = "";
        String challenge = "";
        String validate = "";
        String seccode = "";
        if (forEntity.getStatusCodeValue() == 200) {
            JSONObject jsonObject = JSONUtil.parseObj(forEntity.getBody());
            Console.log("1. 成功申请captcha验证码：");
            Console.log("challenge = {}", jsonObject.getByPath("data.geetest.challenge").toString());
            challenge = jsonObject.getByPath("data.geetest.challenge").toString();
            Console.log("gt = {}", jsonObject.getByPath("data.geetest.gt").toString());
            Console.log("请打开网页：{}，手动进行验证，并按照下面提示输入返回结果（按回车键结束输入）", LOGIN_CAPTCHA_VALIDATOR_URL);
            Console.log("请输入 validate：");
            validate = Console.input();
            Console.log("请输入 seccode：");
            seccode = Console.input();
            Console.log("validate = {}, seccode = {}", validate, seccode);
            token = jsonObject.getByPath("data.token").toString();
        }
        // send
        MultiValueMap<String, String> paramMap = new LinkedMultiValueMap<String, String>(7);
        paramMap.add("cid", "86");
        paramMap.add("tel", "18037193205");
        paramMap.add("token", token);
        paramMap.add("challenge", challenge);
        paramMap.add("validate", validate);
        paramMap.add("seccode", seccode);
        paramMap.add("source", "main-fe-header");
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        httpHeaders.set("APP-KEY", "android64");
        httpHeaders.set("Buvid", "andro16WEG1AEW1G98B181D6B18S9Bid641");
        httpHeaders.set("authority", "android641");
        httpHeaders.set("cookie", "buvid3=5A8BEDB0-E7CC-E57C-26AB-1F9E954E3F5813664infoc; b_nut=1699404813; i-wanna-go-back=-1; b_ut=7; _uuid=C1EBB5F1-10E10F-8F78-10FA1-64F10245161010516833infoc; buvid4=614DAFB6-9951-0590-DD1D-C915E355D9FC14414-023110808-AsDi2%2Fv1r4A7TyrTiKSXhQ%3D%3D; home_feed_column=5; fingerprint=5293d81feba8c0ab14c1d4cd4305a91e; buvid_fp_plain=undefined; browser_resolution=1581-950; bp_video_offset_2644599=889688761538969671; bili_ticket=eyJhbGciOiJIUzI1NiIsImtpZCI6InMwMyIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDYyNTExODgsImlhdCI6MTcwNTk5MTkyOCwicGx0IjotMX0.sJzhB0WdqcQoQmd3udSHgsAuW4WgPN3zOMmOaPP6mdo; bili_ticket_expires=1706251128; sid=5wlmrnfi; enable_web_push=DISABLE; header_theme_version=CLOSE; b_lsid=3223F47F_18D353DBB41; bsource=search_bing; buvid_fp=5293d81feba8c0ab14c1d4cd4305a91e");
        httpHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
        httpHeaders.set("env", "prod");
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<MultiValueMap<String, String>>(paramMap, httpHeaders);
        ResponseEntity<String> exchange =
                restTemplate.exchange(LOGIN_WEB_SEND_SMS_URL, HttpMethod.POST, requestEntity, String.class);
        Console.log("短信发送请求结果:", exchange.getBody());
        String captchaKey = JSONUtil.parse(exchange.getBody()).getByPath("data.captcha_key").toString();
        // login
        Console.log("请输入 验证码：");
        String smsCode = Console.input();

        MultiValueMap<String, String> loginParamMap = new LinkedMultiValueMap<String, String>(7);
        loginParamMap.add("cid", "86");
        loginParamMap.add("tel", "18037193205");
        loginParamMap.add("code", smsCode);
        loginParamMap.add("captcha_key", captchaKey);
        loginParamMap.add("source", "main_web");


        HttpEntity<MultiValueMap<String, String>> loginReq = new HttpEntity<MultiValueMap<String, String>>(loginParamMap, httpHeaders);
        ResponseEntity<String> loginExchange =
                restTemplate.exchange(LOGIN_WEB_SEND_SMS_URL, HttpMethod.POST, loginReq, String.class);
        Console.log("短信发送请求结果:", loginExchange.getBody());
    }

    public void loginQrCodeHandle() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, InterruptedException {
        ResponseEntity<String> forEntity = restTemplate.getForEntity(LOGIN_WEB_QRCODE_GENERATE_URL, String.class);
        String qrcodeKey = "";
        if (forEntity.getStatusCodeValue() == 200) {
            JSONObject jsonObject = JSONUtil.parseObj(forEntity.getBody());
            Console.log("1. 成功获取二维码：");
            Console.log("url = {}", jsonObject.getByPath("data.url").toString());
            qrcodeKey = jsonObject.getByPath("data.qrcode_key").toString();
        }
        ResponseEntity<String> qrcodeResult = null;
        JSONObject qrCodeJson = null;
        while (true) {
            Thread.sleep(2000);
            qrcodeResult = restTemplate.getForEntity(String.format(LOGIN_WEB_QRCODE_URL, qrcodeKey), String.class);
            qrCodeJson = JSONUtil.parseObj(qrcodeResult.getBody());
            if ("0".equals(qrCodeJson.getByPath("data.code").toString())) {
                Console.log("检查二维码状态：{}", qrcodeResult.getBody());
                Console.log("登录成功");
            } else {
                Console.log("检查二维码状态：{}", qrcodeResult.getBody());
            }
        }
    }


    public String encodePwd(String username, String pwd) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        ResponseEntity<String> forEntity = restTemplate.getForEntity(LOGIN_WEB_KEY_URL, String.class);
        if (forEntity.getStatusCodeValue() == 200) {
            JSONObject jsonObject = JSONUtil.parseObj(forEntity.getBody());
            Console.log("2. 成功获取密码加密密钥：");
            String key = jsonObject.getByPath("data.key", String.class);
            String hash = jsonObject.getByPath("data.hash", String.class);
            String[] split = key.split("\n");
            String newKey = split[1] + split[2] + split[3] + split[4];
            //进行加密
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(newKey));
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.PUBLIC_KEY, publicKey);
            byte[] bytes = cipher.doFinal((hash + pwd).getBytes());
            pwd = Base64.encode(bytes);
        }
        return pwd;
    }


    // 获取动态列表
    public void dynamicList() throws InterruptedException {

        Console.log("当前的cookie={}", LOCAL_COOKIE);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("cookie", LOCAL_COOKIE);

        ResponseEntity<String> forEntity = restTemplate.exchange(WEB_DYNAMIC_URL, HttpMethod.GET, new HttpEntity<Object>(httpHeaders), String.class);
        JSONArray byPath = (JSONArray) JSONUtil.parse(forEntity.getBody()).getByPath("data.items");
        Map<String, Object> reqBody = new HashMap<String, Object>();
        ResponseEntity<String> thumbRes;
        String[] split = LOCAL_COOKIE.split("bili_jct=");
        String[] split1 = split[1].split("; ");
        String csrf = split1[0];
        for (Object o : byPath) {
            Thread.sleep(2000);
            String idStr = JSONUtil.parse(o).getByPath("id_str").toString();
            reqBody.clear();
            reqBody.put("dyn_id_str", idStr);
            reqBody.put("up", 1);
            thumbRes = restTemplate.exchange(String.format(WEB_THUMB_URL, csrf), HttpMethod.POST, new HttpEntity<Map<String, Object>>(reqBody, httpHeaders), String.class);
            Console.log("点赞任务运行结果，id_str={}, result={}", idStr, thumbRes.getBody().toString());

        }


    }

    // 检查cookie 状态
    public void cookieInfo() throws InterruptedException, InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("cookie", LOCAL_COOKIE);
        Console.log("当前的cookie={}", LOCAL_COOKIE);
        Console.log("当前的refreshToken={}", LOCAL_REFRESH_TOKEN);
        ResponseEntity<String> forEntity = restTemplate.exchange(WEB_COOKIE_INFO_URL, HttpMethod.GET, new HttpEntity<Object>(httpHeaders), String.class);
        if ("0".equals(JSONUtil.parse(forEntity.getBody()).getByPath("code").toString())) {
            return;
        }
        String csrf = "";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(WEB_COOKIE_REFRESH_PUBLIC_KEY));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));

        byte[] encryptedBytes = cipher.doFinal(("refresh_" + System.currentTimeMillis()).getBytes());
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : encryptedBytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        Console.log("CRSF = {}", stringBuilder.toString());
        csrf = stringBuilder.toString();
        httpHeaders.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
//        httpHeaders.setAcceptCharset(Collections.singletonList(StandardCharsets.UTF_8));

        String body = HttpRequest.get(String.format(WEB_CSRF_URL, csrf)).cookie(LOCAL_COOKIE).execute().body();


        Document parse = Jsoup.parse(body);

        String refreshCrsf = parse.getElementById("1-name").childNodes().get(0).toString().replace("\n", "");
        String[] split = LOCAL_COOKIE.split("bili_jct=");
        String[] split1 = split[1].split("; ");
        csrf = split1[0];

        MultiValueMap<String, String> cookieRefreshMap = new LinkedMultiValueMap<>();
        cookieRefreshMap.add("csrf", csrf);
        cookieRefreshMap.add("refresh_csrf", refreshCrsf);
        cookieRefreshMap.add("source", "main_web");
        cookieRefreshMap.add("refresh_token", LOCAL_REFRESH_TOKEN);
        httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<String> cookieRefreshResult = restTemplate.exchange(WEB_COOKIE_REFRESH_URL, HttpMethod.POST,
                new HttpEntity<MultiValueMap<String, String>>(cookieRefreshMap, httpHeaders), String.class);
        JSON cookieRefreshParse = JSONUtil.parse(cookieRefreshResult.getBody());
        String newLocalCookie = cookieRefreshResult.getHeaders().get("Set-Cookie").toString().replace("[", "").replace("]", "");
        String newRefresh_token = cookieRefreshParse.getByPath("data.refresh_token").toString();

        Console.log("正在尝试刷新cookie， 新的LOCAL_COOKIE = {}",
                newLocalCookie);
        Console.log("正在尝试刷新cookie， 新的LOCAL_REFRESH_TOKEN = {}",
                newRefresh_token);

        MultiValueMap<String, String> confirmCookieRefreshMap = new LinkedMultiValueMap<>();
        String[] split2 = newLocalCookie.split("bili_jct=");
        String[] split3 = split2[1].split("; ");
        String newCsrf = split3[0];

        confirmCookieRefreshMap.add("csrf", newCsrf);
        confirmCookieRefreshMap.add("refresh_token", LOCAL_REFRESH_TOKEN);
        httpHeaders.clear();
        httpHeaders.set("cookie", newLocalCookie);
        ResponseEntity<String> confirmCookieRefreshResult = restTemplate.exchange(WEB_COOKIE_CONFIRM_REFRESH_URL, HttpMethod.POST,
                new HttpEntity<MultiValueMap<String, String>>(confirmCookieRefreshMap, httpHeaders), String.class);

        Console.log("正在尝试确认刷新cookie， result : {}", confirmCookieRefreshResult.getBody());
        LOCAL_REFRESH_TOKEN = newRefresh_token;
        LOCAL_COOKIE = newLocalCookie;
        Console.log("刷新cookie成功！ O(∩_∩)O");
        Console.log("LOCAL_COOKIE = {}", LOCAL_COOKIE.replace("[", "").replace("]", ""));
        Console.log("LOCAL_REFRESH_TOKEN = {}", LOCAL_REFRESH_TOKEN);
    }

    public byte[] toByteArray(long value) {
        return ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(System.currentTimeMillis()).array();
    }


    @PostConstruct
    private void run() {
        AppProvider app = SpringUtil.getBean("appProvider");

        byte[] decode = Base64.decode(LOCAL_COOKIE);
        LOCAL_COOKIE = new String(decode);

        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                while (true) {
                    System.out.println("\n\n\n");
                    Console.log("时间：{}，新的任务开始ヾ(≧▽≦*)o", DateUtil.now());

                    try {
                        app.cookieInfo();
                        app.dynamicList();
                        Console.log("bilibili定时任务结束，1小时后见啦！ψ(｀∇´)ψ");
                        Thread.sleep(3600000);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        Thread thread = new Thread(runnable);
        thread.start();
    }
}
