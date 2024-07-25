//  generate random password
export function generatePass(length = 9): string {
    const charset = "ab1cdef!ghijk2lm@no3pq#rstuv4wx$yz5A%BCD6EFG7%HIJKL8^NOPQR&S9TUVWXY0Z0123*456789.";
    let retVal = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;
}

// generate OTP
export function generateOTP(length = 4): string {
    const charset = "0123456789";
    let retVal = '';
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;
}

export function generateId(pre: string, length: number) {
    const randomId = Math.floor(Math.random() * 10000).toString().padStart(length, '0');
    return `${pre}-${randomId}`;
}
