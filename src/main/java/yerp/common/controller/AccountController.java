package yerp.common.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import yerp.common.annotation.CommonParam;
import yerp.common.service.CommonService;
//import yerp.common.service.SSOService;
import yerp.common.util.APIResponse;
import yerp.common.util.CommonUtil;
import yerp.common.util.ConstantUtil;
import yerp.common.util.ParameterUtil;
import yerp.common.util.StringUtil;
import yerp.common.valid.Required;
import yerp.common.valid.Validator;

//import egovframework.ext.utils.UserAgentUtil;
//import egovframework.ext.vo.UserVO;
//import egovframework.rte.fdl.property.EgovPropertyService;

@RestController
@RequestMapping("/account")
public class AccountController {
	@Autowired
	private CommonService commonService;
	
//	@Autowired
//	private SSOService ssoService;
	
//	@Autowired
//	protected EgovPropertyService properties;
	
	@RequestMapping("/sessionInfo")
	public String getSessionInfo(HttpSession session) {
		baseInfo(null, session);
		JSONObject result = new JSONObject();
		Enumeration<String> keys = session.getAttributeNames();
		while (keys.hasMoreElements()) {
			String key = keys.nextElement();
			result.put(key, session.getAttribute(key));
		}
		return result.toString();
	}
	
	@GetMapping("/getMyInfo")
	public ResponseEntity<JSONObject> getMyInfo(@CommonParam Map<String, Object> parameter) {
	    JSONArray sqlResult = null;
	    APIResponse response = new APIResponse();
	    try {
	        sqlResult = commonService.selectList("system.account.getUserInfoForMainPopup", parameter);
	        response.setResponse(sqlResult);
	    } catch (Exception e) {
	        response.setResponseForError(e);
	    }
	    return response.getEntity();
	}
	
	@PostMapping("/setMyInfo")
	public ResponseEntity<JSONObject> setMyInfo(@CommonParam Map<String, Object> parameter) {
	    APIResponse response = new APIResponse();
	    try {
	        JSONObject normal = ParameterUtil.getNormal(parameter);
	        Validator validator = new Validator();
	        validator.add(new Required(new String[]{"TelNo", "ZipNo", "JilmunGb"}));
	
	        JSONArray validResult = validator.run(normal);
	        if (validator.isPass()) {
	            response.setResponse(commonService.normalProcess("system.account.setUserInfoForMainPopup", parameter));
	        } else {
	            response.setResponseForValidation(validResult);
	        }
	
	    } catch (Exception e) {
	        response.setResponseForError(e);
	    }
	    return response.getEntity();
	}
	
	@PostMapping(value = "/login")
	public ResponseEntity<JSONObject> loginProc(@CommonParam Map<String, Object> parameter, HttpSession session, HttpServletRequest request) {
	    APIResponse response = new APIResponse();
	    JSONObject sqlResult = null;
	    try {
	        sqlResult = commonService.selectOne("system.account.getUserInfo", parameter);
	        if (sqlResult != null && !sqlResult.isEmpty()) {
	            response.setResponse("success");
	            session.setAttribute(ConstantUtil.SESSION_USER_ID, sqlResult.get("USER_IDNT"));
	            session.setAttribute(ConstantUtil.SESSION_USER_NM, sqlResult.get("USER_KRNM"));
	            session.setAttribute(ConstantUtil.SESSION_IP, CommonUtil.getRemoteAddr(request));
	            setInfoToSession(parameter, session);
	        } else {
	            response.setResponse("fail");
	        }
	    } catch (Exception e) {
	        e.printStackTrace();
	        response.setResponse("error");
	    }
	
	    return response.getEntity();
	}
	
//	@PostMapping(value = "/tokenValid")
//	public ResponseEntity<JSONObject> tokenValid(@CommonParam Map<String, Object> parameter, HttpSession session, HttpServletRequest request, HttpServletResponse res) {
//	    APIResponse response = new APIResponse();
//	    try {
//	        Cookie[] cookieArr = request.getCookies();
//	        String cookieAccessToken = "";
//	        String cookieRefreshToken = "";
//	        if (cookieArr != null) {
//	            for (int i = 0; i < cookieArr.length; i++) {
//	                if ("access_token".equals(cookieArr[i].getName())) {
//	                    cookieAccessToken = cookieArr[i].getValue();
//	                }
//	
//	                if ("refresh_token".equals(cookieArr[i].getName())) {
//	                    cookieRefreshToken = cookieArr[i].getValue();
//	                }
//	            }
//	        }
//	        String sesRefreshToken = (String) request.getSession().getAttribute("refresh_token");
//	        if (StringUtils.isEmpty(cookieRefreshToken)) {
//	            if (StringUtils.isEmpty(sesRefreshToken)) {
//	                response.setResponse("nextAction", "OUT_A");            // 세션에 refresh_token이 없을 경우 통합로그인 화면으로 이동
//	            } else {
//	                response.setResponse("nextAction", "OUT_B");            // 세션에 refresh_token이 있으면 로그아웃으로 통해 refresh_token 제거 및 통합로그인 화면 이동
//	            }
//	        } else {
//	            if (StringUtils.isEmpty(sesRefreshToken)) {
//	                response.setResponse("nextAction", "LOGIN_A");
//	            } else {
//	                if ((!StringUtils.isEmpty(cookieRefreshToken) && !StringUtils.isEmpty(sesRefreshToken))
//	                        && cookieRefreshToken.equals(sesRefreshToken)) {
//	
//	                    parameter.put("access_token", cookieAccessToken);
//	                    parameter.put("refresh_token", cookieRefreshToken);
//	                    parameter.put("client_ip", request.getRemoteAddr());
//	                    JSONObject responseObject = ssoService.tokenValidation(parameter);
//	                    if (!responseObject.get("error").equals("0000")) {
//	                        response.setResponse("nextAction", "OUT_B");
//	                        response.setResponse("response", responseObject);
//	                    }
//	                } else {
//	                    JSONObject responseForRefresh = ssoService.getRefreshToken(parameter);
//	                    if (responseForRefresh.get("error").equals("0000")) {
//	                        Cookie cookie = new Cookie("access_token", (String) responseForRefresh.get("access_token"));
//	                        /* 실제 서버에 배포시 주석 제거*/
//	                        /*cookie.setDomain(".shingu.ac.kr"); */
//	                        cookie.setDomain("www.testdemo.co.kr");
//	                        /**/
//	                        cookie.setPath("/");
//	                        cookie.setMaxAge(Integer.parseInt((String) responseForRefresh.get("expires_in")));
//	                        res.addCookie(cookie);
//	                        response.setResponse("nextAction", "LOGIN_A");
//	                    } else {
//	                        response.setResponse("nextAction", "OUT_B");
//	                        response.setResponse("response", responseForRefresh);
//	                    }
//	                }
//	            }
//	        }
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	        response.setResponse("error");
//	    }
//	
//	    return response.getEntity();
//	}
	
//	@RequestMapping(value = "/ssoLogin")
//	public ResponseEntity<JSONObject> ssoLoginProc(@CommonParam Map<String, Object> parameter, HttpSession session, HttpServletRequest request, HttpServletResponse res) {
//	    APIResponse response = new APIResponse();
//	    String messageForGetRequest = "";
//	    try {
//	        //쿠키정보 확인
//	        Cookie[] cookieArr = request.getCookies();
//	
//	        String cookieRefreshToken = "";
//	        String cookieAccesToken = "";
//	        if (cookieArr != null) {
//	
//	            for (int i = 0; i < cookieArr.length; i++) {
//	                if ("refresh_token".equals(cookieArr[i].getName())) {
//	                    cookieRefreshToken = cookieArr[i].getValue();
//	                }
//	                if ("access_token".equals(cookieArr[i].getName())) {
//	                    cookieAccesToken = cookieArr[i].getValue();
//	                }
//	            }
//	            parameter.put("access_token", cookieAccesToken);
//	            parameter.put("refresh_token", cookieRefreshToken);
//	            parameter.put("client_ip", request.getRemoteAddr());
//	            JSONObject responseObject = ssoService.getRefreshToken(parameter);
//	            if (responseObject.get("error").equals("0000")) {
//	                JSONObject responseForUserInfo = ssoService.getUserInfo(parameter);
//	                if (responseForUserInfo.get("error").equals("0000")) {
//	                    response.setResponse("success");
//	                    session.setAttribute(ConstantUtil.SESSION_USER_ID, responseForUserInfo.get("user_id"));
//	                    session.setAttribute(ConstantUtil.SESSION_USER_NM, responseForUserInfo.get("user_nm"));
//	                    session.setAttribute(ConstantUtil.SESSION_IP, CommonUtil.getRemoteAddr(request));
//	                    session.setAttribute("refresh_token", cookieRefreshToken);
//	                    session.setAttribute("isSSOLogin", "Y");
//	                    setInfoToSession(parameter, session);
//	                } else {
//	                    response.setResponse("fail", responseForUserInfo);
//	                    messageForGetRequest = (String) responseForUserInfo.get("error");
//	                }
//	            } else {
//	                response.setResponse("fail", responseObject);
//	                messageForGetRequest = (String) responseObject.get("error");
//	            }
//	        }
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	        response.setResponse("error");
//	    }
//	    try {
//	        if (request.getMethod().equalsIgnoreCase("get")) {
//	            if (messageForGetRequest.equals("")) {
//	                res.sendRedirect("/");
//	            } else {
//	                //res.sendRedirect("/page/login#msg="+messageForGetRequest);
//	                res.sendRedirect("/");
//	            }
//	        }
//	    } catch (IOException e) {
//	        e.printStackTrace();
//	    }
//	    return response.getEntity();
//	}
	
	@PostMapping(value = "/logout")
	public ResponseEntity<JSONObject> logout(@CommonParam Map<String, Object> parameter, HttpSession session, HttpServletRequest request, HttpServletResponse res) {
		APIResponse response = new APIResponse();
		try {
			session.invalidate();
			Cookie[] cookies = request.getCookies();
			String accessToken = "";
			if (cookies != null) {
				for (int i = 0; i < cookies.length; i++) {
					if ("access_token".equals(cookies[i].getName())) {
						accessToken = cookies[i].getValue();
					}
				}
			}
//	        if (!StringUtil.isNull(accessToken)) {
//	            parameter.put("access_token", accessToken);
//	            parameter.put("client_ip", request.getRemoteAddr());
//	            ssoService.logout(parameter);
//	        }
			/* 실제 서버에 배포시 주석 제거 */
			Cookie access_token = new Cookie("access_token", null);
			access_token.setMaxAge(0);
//			access_token.setDomain(".testdemo.co.kr");
			access_token.setDomain("localhost:8080");
			access_token.setPath("/");
			res.addCookie(access_token);
			
			Cookie refresh_token = new Cookie("refresh_token", null);
			refresh_token.setMaxAge(0);
//			refresh_token.setDomain(".testdemo.co.kr");
			refresh_token.setDomain("localhost:8080");
			res.addCookie(refresh_token);
			
			//이클래스 연동 쿠키 제거
			Cookie cookie_1 = new Cookie("UniCookie_1", null);
//			cookie_1.setDomain("testdemo.co.kr");
			cookie_1.setDomain("localhost:8080");
			cookie_1.setPath("/");
			res.addCookie(cookie_1);
			
			Cookie cookie_2 = new Cookie("UniCookie_2", null);
//			cookie_2.setDomain("testdemo.co.kr");
			cookie_2.setDomain("localhost:8080");
			
			cookie_2.setPath("/");
			res.addCookie(cookie_2);
			
			Cookie cookie_12 = new Cookie("UniCookie_12", null);
			
//			cookie_12.setDomain("testdemo.co.kr");
			cookie_12.setDomain("localhost:8080");
			cookie_12.setPath("/");
			res.addCookie(cookie_12);
			/**/
			response.setResponse("success");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return response.getEntity();
	}
	
//	@GetMapping(value = "/getQRCodeForOTP")
//	public ResponseEntity<JSONObject> getQRCode(@CommonParam Map<String, Object> parameter, HttpSession session, HttpServletRequest request) {
//	    APIResponse response = new APIResponse();
//	    try {
//	        JSONObject common = ParameterUtil.getCommon(parameter);
//	        String userId = (String) common.get(ConstantUtil.SESSION_USER_ID);
//	
//	        parameter.put("user_id", userId);
//	        parameter.put("client_ip", request.getRemoteAddr());
//	        JSONObject responseObject = ssoService.getQRCode(parameter);
//	
//	        response.setResponse(responseObject);
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	        response.setResponse("error");
//	    }
//	
//	    return response.getEntity();
//	}
	
	@GetMapping(value = "/getQRCode")
	public void getQRCodeForStudent(@CommonParam Map<String, Object> parameter, HttpSession session, HttpServletRequest request, HttpServletResponse res) {
		QRCodeWriter q = new QRCodeWriter();
		try {
			JSONObject common = ParameterUtil.getCommon(parameter);
			String userId = (String) common.get(ConstantUtil.SESSION_USER_ID);
			res.setHeader("Content-Disposition", "attachment; filename=qrcode.png");
			BitMatrix bitMatrix = q.encode(userId, BarcodeFormat.QR_CODE, 170, 170);
			MatrixToImageWriter.writeToStream(bitMatrix, "png", res.getOutputStream());
			res.flushBuffer();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void setInfoToSession(Map<String, Object> parameter, HttpSession session, String... nonSsoLogin) {
		JSONObject sqlResultForAddSession = null;
		try {
			JSONObject customParamter = new JSONObject();
			customParamter.put("USER_IDNT", session.getAttribute(ConstantUtil.SESSION_USER_ID));
			ParameterUtil.addCustom(parameter, customParamter);
//			System.out.println(parameter);
//			sqlResultForAddSession = commonService.selectOne("system.account.getUserInfoForAddSession", parameter);
			JSONObject result = commonService.selectProcess("system.account.getUserInfoForAddSession", parameter);
//			System.out.println(result);
			List resultList = (List) result.get(ConstantUtil.PROC_RESULT);
			
			sqlResultForAddSession = (JSONObject) resultList.get(0);
			
			if (sqlResultForAddSession != null && !sqlResultForAddSession.isEmpty()) {
				/* 년도, 학기정보 session 에 추가 시작 */
				JSONObject yyHgParameter = new JSONObject();
				
				ParameterUtil.addCustom(yyHgParameter, customParamter);
				
				JSONObject scheduleObj = commonService.selectProcess("system.component.getYearHakgi", yyHgParameter);
//				System.out.println(scheduleObj);
//				List<Map> scheduleList = (List) scheduleObj.get(ConstantUtil.PROC_RESULT);
				List<Map> scheduleInfo = (List) scheduleObj.get(ConstantUtil.PROC_RESULT);
				
//				JSONArray scheduleInfo = ParameterUtil.convertJSONArray(String.valueOf(scheduleList));
				
//				System.out.println(scheduleInfo);
				
				JSONObject objectForSession = new JSONObject();
//				for (Object array : scheduleInfo) {
//					List<Map> objectArray = (ArrayList) array;
//					for (Object object : objectArray) {
//						JSONObject schedule = (JSONObject) object;
//						Set<String> keySet = schedule.keySet();
//						for (String key : keySet) {
//							objectForSession.put(key, schedule.get(key));
//						}
//					}
//				}
				
				for (Object object : scheduleInfo) {
					JSONObject schedule = (JSONObject) object;
					Set<String> keySet = schedule.keySet();
					for (String key : keySet) {
						objectForSession.put(key, schedule.get(key));
					}
				}
				
				session.setAttribute("schedule", objectForSession);
				/* 년도, 학기정보 session 에 추가 종료 */
				
//				System.out.println(sqlResultForAddSession);
				
				/* 신구대학교 사용자 정보 추가 시작 */
				for (Object object : sqlResultForAddSession.keySet()) {
					String key = (String) object;
					session.setAttribute(key, sqlResultForAddSession.get(key));
				}
				/* 신구대학교 사용자 정보 추가 종료 */
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/*session.schedule 화면오픈할때 세팅*/
	public void baseInfo(Map<String, Object> parameter, HttpSession session) {
	
		try {
			/* 년도, 학기정보 session 에 추가 시작 */
			JSONObject customParamter = new JSONObject();
			customParamter.put("USER_IDNT", session.getAttribute(ConstantUtil.SESSION_USER_ID));
			JSONObject yyHgParameter = new JSONObject();
			
			ParameterUtil.addCustom(yyHgParameter, customParamter);
			
			JSONArray scheduleInfo = commonService.selectList("system.component.getYearHakgi", yyHgParameter);
			JSONObject objectForSession = new JSONObject();
			for (Object array : scheduleInfo) {
				List<Map> objectArray = (ArrayList) array;
				for (Object object : objectArray) {
					JSONObject schedule = (JSONObject) object;
					Set<String> keySet = schedule.keySet();
					for (String key : keySet) {
						objectForSession.put(key, schedule.get(key));
					}
				}
			}
			session.setAttribute("schedule", objectForSession);
			/* 년도, 학기정보 session 에 추가 종료 */
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * NON_SSO_LOGIN
	 * */
	@RequestMapping(value = "/nonSsoLogin")
	public ResponseEntity<JSONObject> loginTest(String userId, String password, HttpSession session, HttpServletRequest request, HttpServletResponse res) {
		APIResponse response = new APIResponse();
		JSONObject parameter = new JSONObject();
		
		JSONObject sqlResult = null;
		
//		// 회원 유효성 체크 플래그
//		boolean userChkFlag = false;
		
//		// 관리자 회원 ID, PW 배열 상수 선언
//		String[][] adminChk = ConstantUtil.USER_ADMIN_ARRAY;
		
//		// 회원 ID, PW 유효성 체크
//		outIdLoop : for(int i=0; i<adminChk.length; i++) {
//			if(userId != null && password != null) {
//				for(int j=0; j<adminChk[i].length; j++) {
//					// 상수 선언된 로그인 정보 체크
//					if(adminChk[i][0].equals(userId) && adminChk[i][1].equals(password)) {
//						userChkFlag = true;
//						break outIdLoop;
//					}
//				}
//			}
//		}
		
		try {
			//+++++++++++++++++++++++++++++++++++++++++++++++++++++
			// 비지니스 로직 시작
			//+++++++++++++++++++++++++++++++++++++++++++++++++++++
			JSONObject customParamter = new JSONObject();
			
			customParamter.put("LOGIN_ID", userId);
			customParamter.put("LOGIN_PWD", password);
//			customParamter.put("C_USER", "");
			
			ParameterUtil.addCustom(parameter, customParamter);
			
			// 존재하는 사용자인지 확인
//			sqlResult = commonService.selectOne("system.account.selectLoginUser", parameter);
			JSONObject result = commonService.selectProcess("system.account.selectLoginUser", parameter);
			
			List<Map> userMap = (List) result.get(ConstantUtil.PROC_RESULT);
			
//			JSONArray userArray = ParameterUtil.convertJSONArray(String.valueOf(userMap));
			
//			JSONParser parser = new JSONParser();
//			JSONObject jsonObject = null;
			
//			try {
//				sqlResult = (JSONObject) parser.parse(String.valueOf(result.get(ConstantUtil.PROC_RESULT)));
//			} catch (ParseException e) {
//				e.printStackTrace();
//			}
			
			sqlResult = (JSONObject) userMap.get(0);
			
//			sqlResult = ParameterUtil.convertJSON(String.valueOf(result == null? "{}" : result.get(ConstantUtil.PROC_RESULT)));
//			String p_usernm = parameter.get("P_USERNM").toString();
//			
//			sqlResult.put("USERID", p_userid);
//			sqlResult.put("USERNM", p_usernm);
			
//			sqlResult = (JSONObject) parameter.get("C_USER");
			
//			JSONObject custom = ParameterUtil.getCustom(parameter);
			
//			System.out.println(sqlResult);
//			System.out.println(result);
//			System.out.println(userMap);
//			System.out.println(userArray);
			
			if (sqlResult != null && !sqlResult.isEmpty()) {
				response.setResponse("success");
				session.setAttribute(ConstantUtil.SESSION_USER_ID, sqlResult.get("USERID"));
				session.setAttribute(ConstantUtil.SESSION_USER_NM, sqlResult.get("USERNM"));
				session.setAttribute(ConstantUtil.SESSION_IP, CommonUtil.getRemoteAddr(request));
				session.setAttribute("isSSOLogin", "N");
				session.setAttribute("nonSsoLogin", "Y");
				setInfoToSession(parameter, session, "Y");
				res.sendRedirect("/");
			}
			else {
				response.setResponse("fail");
				res.sendRedirect("/page/login?message=Y");
			}
			
			// 정상 로그인시 회원 아이디 9999905세팅 후 USER_INFO 조회 및 세션 세팅 (프로시저 - dbo.SG_GAT_LoginInfo_SELECT)
//			/*if(userChkFlag) {
//				userId = "9999905";
//				response.setResponse("success");
//				session.setAttribute(ConstantUtil.SESSION_USER_ID, userId);
//				session.setAttribute(ConstantUtil.SESSION_USER_NM, "admin");
//				session.setAttribute(ConstantUtil.SESSION_IP, CommonUtil.getRemoteAddr(request));
//				session.setAttribute("isSSOLogin", "N");
//				session.setAttribute("nonSsoLogin", "Y");
//				setInfoToSession(parameter, session, "Y");
//				res.sendRedirect("/");
//			}
//			// 실패시 로그인화면 리다이렉트
//			else {
//				response.setResponse("fail");
//				res.sendRedirect("/page/nonSsoLogin?message=Y");
//			}*/
		} catch (Exception e) {
			e.printStackTrace();
			response.setResponse("error");
	//		res.sendRedirect("/page/login?message=Y");
		}
		return response.getEntity();
	}
	
}
