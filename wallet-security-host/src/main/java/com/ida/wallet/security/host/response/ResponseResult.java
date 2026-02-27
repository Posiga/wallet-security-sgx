package com.ida.wallet.security.host.response;


import com.ida.wallet.security.host.enums.ErrorCodeEnum;

import java.io.Serializable;

public class ResponseResult<T> implements Serializable {
    private static final long serialVersionUID = 1L;

    protected String msg;

    protected Integer code = ErrorCodeEnum.SUCCESS.getCode();

    protected T data;

    public ResponseResult(){}

    public ResponseResult(T data){
        this.data = data;
    }

    public ResponseResult(String msg, Integer code){
        this.msg = msg;
        this.code = code;
    }

    public ResponseResult(String msg, Integer code, T data){
        this.msg = msg;
        this.code = code;
        this.data = data;
    }

    public static <T> ResponseResult<T> success(){
        return new ResponseResult();
    }

    public static <T> ResponseResult<T> success(T data){
        return new ResponseResult(data);
    }

    public static <T> ResponseResult<T> fail(String msg, Integer code) {
        return new ResponseResult(msg, code);
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
