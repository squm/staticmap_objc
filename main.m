#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import "Say.h"

NSString *
cc_base64_encode(NSData *data) {
	NSString *base64 = [data base64EncodedStringWithOptions:0];

	NSMutableString *strip = [base64 mutableCopy];

	const NSRange rng = NSMakeRange(0, strip.length);

	// Exact character-by-character equivalence
	const NSStringCompareOptions opt = NSLiteralSearch;

	[strip replaceOccurrencesOfString:@"+"
			       withString:@"-"
				  options:opt
				    range:rng];

	[strip replaceOccurrencesOfString:@"/"
			       withString:@"_"
				  options:opt
				    range:rng];

	return [strip copy];
}
NSData *
cc_base64_decode(NSString *base64) {
	NSMutableString *strip = [base64 mutableCopy];

	const NSRange rng = NSMakeRange(0, strip.length);

	// Exact character-by-character equivalence
	const NSStringCompareOptions opt = NSLiteralSearch;

	[strip replaceOccurrencesOfString:@"-"
			       withString:@"+"
				  options:opt
				    range:rng];

	[strip replaceOccurrencesOfString:@"_"
			       withString:@"/"
				  options:opt
				    range:rng];

	NSData *data = [[NSData alloc] initWithBase64EncodedString:strip options:0];

	return data;
}
NSString *
cc_hmac64_key(NSString *const key, NSString *const msg) {
	NSData *const data_key = cc_base64_decode(key);
	NSData *const data_msg = [msg dataUsingEncoding:NSUTF8StringEncoding];

	const CC_LONG len_dig = CC_SHA1_DIGEST_LENGTH;
	unsigned char digest[len_dig];

	CCHmac(
		kCCHmacAlgSHA1,
		data_key.bytes, data_key.length,
		data_msg.bytes, data_msg.length,
		digest
	);

	NSData *const data_dig = [NSData dataWithBytes:digest length:len_dig];
	return cc_base64_encode(data_dig);
}
NSString *
cc_signature(NSString *const key, NSString *url) {
	NSMutableString *strip = [url mutableCopy];

	NSRange rng = NSMakeRange(0, strip.length);

	// Search is limited to start of source string
	NSStringCompareOptions opt = NSAnchoredSearch;

	[strip replaceOccurrencesOfString:@"http://maps.googleapis.com"
			       withString:@""
				  options:opt
				    range:rng];

	[strip replaceOccurrencesOfString:@"https://maps.googleapis.com"
			       withString:@""
				  options:opt
				    range:rng];

	NSString *msg = strip;

	NSString *signature = cc_hmac64_key(key, msg);

	url = [url stringByAppendingString:@"&signature="];
	url = [url stringByAppendingString:signature];

	return url;
}
int
main() {
	NSString *const key = @"key";
	NSString *const url = @"https://maps.googleapis.com/maps/api/staticmap?format=png";

	say("%@", cc_signature(key, url));

	return 0;
}

