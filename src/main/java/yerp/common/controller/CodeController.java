package yerp.common.controller;

import yerp.common.annotation.CommonParam;
import yerp.common.service.CommonService;
import yerp.common.util.APIResponse;
import yerp.common.util.ConstantUtil;
import yerp.common.util.ParameterUtil;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/code")
public class CodeController {
    @Autowired
    private CommonService commonService;

	@RequestMapping("/getCommonCode")
	public ResponseEntity<JSONObject> get(@CommonParam Map<String, Object> parameter) {
        JSONArray sqlResult = new JSONArray();
        APIResponse response = new APIResponse();
        try {
            JSONObject normal = ParameterUtil.getNormal(parameter);
            JSONArray param = (JSONArray) normal.get("param");
            JSONArray paramArray;
            JSONObject custom;
            for(Object outerArray : param) {
                paramArray = (JSONArray) outerArray;
                custom = new JSONObject();
                for(int i=1; i<=7; i++) {
                    String value = "";
                    try {
                        value = (String) paramArray.get(i-1);
                    } catch(IndexOutOfBoundsException iobe) {}

                    custom.put("param"+i, value);
                    ParameterUtil.addCustom(parameter, custom);
                }
                sqlResult.add(commonService.selectList("system.code.getCommonCode", parameter));
            }

            response.setResponse(sqlResult);
        } catch (Exception e) {
            response.setResponseForError(e);
        }
        return response.getEntity();
	}
	
	@RequestMapping("getDeptCode")
	public ResponseEntity<JSONObject> getDeptCode(@CommonParam Map<String, Object> parameter) {
		APIResponse response = new APIResponse();
		try {
			response.setResponse(commonService.selectList("system.code.getDeptCode", parameter));
		} catch (Exception e) {
			response.setResponseForError(e);
		}
		return response.getEntity();
	}
	
	@RequestMapping("getPsDeptCode")
	public ResponseEntity<JSONObject> getPsDeptCode(@CommonParam Map<String, Object> parameter) {
		APIResponse response = new APIResponse();
		try {
			response.setResponse(commonService.selectList("system.code.getPsDeptCode", parameter));
		} catch (Exception e) {
			response.setResponseForError(e);
		}
		return response.getEntity();
	}
}
