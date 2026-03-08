export function httpError(statusOrCode, codeOrMessage, messageOrDetails, details) {
    const hasExplicitStatus = typeof statusOrCode === "number";

    const status = hasExplicitStatus ? statusOrCode : undefined;
    const code = hasExplicitStatus ? codeOrMessage : statusOrCode;
    const message = hasExplicitStatus ? messageOrDetails : codeOrMessage;
    const resolvedDetails = hasExplicitStatus ? details : messageOrDetails;

    const error = new Error(message);
    if (status) {
        error.status = status;
    }
    error.code = code;
    error.isAppError = true;

    if (resolvedDetails) {
        error.details = resolvedDetails;
    }

    return error;
}
