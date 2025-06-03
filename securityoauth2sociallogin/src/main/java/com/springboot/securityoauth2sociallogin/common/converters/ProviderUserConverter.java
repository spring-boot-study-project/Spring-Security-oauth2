package com.springboot.securityoauth2sociallogin.common.converters;

public interface ProviderUserConverter<T, R> {
    R convert(T t);
}
