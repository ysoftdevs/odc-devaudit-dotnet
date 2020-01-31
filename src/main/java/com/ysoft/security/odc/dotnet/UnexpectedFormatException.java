package com.ysoft.security.odc.dotnet;

import java.io.IOException;

public class UnexpectedFormatException extends IOException {
    public UnexpectedFormatException(String msg) {
        super(msg);
    }
}
