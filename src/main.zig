const std = @import("std");
const secp2 = @import("sepc");
const rand = std.crypto.random;
const print = std.debug.print;
const webui = @import("webui");
const sha = std.crypto.hash.sha2.Sha256;
const ripemd160 = @import("ripemd160");
const base58 = @import("base58-zig");
// we use @embedFile to embed html
const html = @embedFile("index.html");

pub fn main() !void {
    var nwin = webui.newWindow();
    _ = nwin.bind("create_key", create_key);
    _ = nwin.bind("checkBln", checkBln);
    _ = nwin.show(html);

    webui.wait();

    webui.clean();
}

fn create_key(e: *webui.Event) void {
    const secp = secp2.Secp256k1.genNew();
    const alloc = std.heap.page_allocator;

    secp.deinit();

    const privkey, const pubkey = secp.generateKeypair(rand);

    const res: [66]u8 = pubkey.toString();

    const prvires: [64]u8 = privkey.toString();

    const wk = alloc.dupeZ(u8, &res) catch unreachable;

    defer alloc.free(wk);

    const stx = std.fmt.allocPrintZ(alloc, "Private key: {s}\n Pubkey {s}", .{ res, prvires }) catch unreachable;

    print("{s}", .{res});
    deriveAddress(&res);

    e.returnString(stx);
}

fn checkBln(e: *webui.Event) void {
    const r = e.getString();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const parse = std.fmt.allocPrintZ(allocator, "https://blockchain.info/q/addressbalance/{s}", .{r}) catch unreachable;
    defer allocator.free(parse);

    const uri = std.Uri.parse(parse) catch unreachable;
    const buf = allocator.alloc(u8, 1024 * 1024 * 4) catch unreachable;
    defer allocator.free(buf);

    var req = client.open(.GET, uri, .{ .server_header_buffer = buf }) catch unreachable;
    defer req.deinit();
    req.send() catch unreachable;
    req.finish() catch unreachable;
    req.wait() catch unreachable;

    var rdr = req.reader();
    const body = rdr.readAllAlloc(allocator, 1024 * 1024 * 4) catch unreachable;
    defer allocator.free(body);

    const formated = allocator.dupeZ(u8, body) catch unreachable;

    const stated = fromSat(formated) catch unreachable;
    e.returnFloat(stated);
    defer allocator.free(formated);
}

fn fromSat(target: []u8) !f64 {
    const res = try std.fmt.parseFloat(f64, target);

    return @divTrunc(res, 100_000_000.0);
}

fn deriveAddress(pubkey: []const u8) void {
    var sha_hash: [sha.digest_length]u8 = undefined;
    sha.hash(pubkey, &sha_hash, .{});
    ripemd160.Ripemd160.hash(b: []const u8, out: *[digest_length]u8, options: Options)
    // Step 2: RIPEMD-160 of the SHA-256 hash
    var ripemd160_hash: [20]u8 = undefined;
    ripemd160.hash(sha_hash[0..], &ripemd160_hash, .{});

    // Step 3: Prepend network byte (0x00 for Bitcoin Mainnet)
    var address_with_prefix: [21]u8 = undefined;
    address_with_prefix[0] = 0x00; // Bitcoin Mainnet prefix
    @memcpy(address_with_prefix[1..], ripemd160_hash[0..]);

    // Step 4: Double SHA-256 of the prefixed address
    var checksum: [4]u8 = undefined;
    var double_sha_hash: [sha.digest_length]u8 = undefined;
    sha.hash(address_with_prefix[0..], &double_sha_hash, .{});
    sha.hash(double_sha_hash[0..], &checksum, .{});

    // Step 5: Concatenate the prefixed address and checksum
    var final_address: [25]u8 = undefined;
    @memcpy(final_address[0..21], address_with_prefix[0..]);
    @memcpy(final_address[21..], checksum[0..]);

    // Step 6: Encode in Base58
    const base58_encoded = base58Encode(final_address[0..]);
    return base58_encoded;
}

pub fn base58Encode(data: []const u8) []const u8 {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const base = 58;

    // Allocate a buffer for the encoded result
    var buffer: [128]u8 = undefined;
    var encoded = buffer[0..];
    var encoded_len: usize = 0;

    // Convert the input data to an integer
    var num: u128 = 0;
    for (data) |byte| {
        num = num * 256 + @as(u128, byte);
    }

    // Encode the number in base58
    while (num > 0) {
        const remainder = @rem(num, base);
        num /= base;

        encoded[encoded_len] = alphabet[remainder];
        encoded_len += 1;
    }

    // Add leading '1's for leading zero bytes in the input
    for (data) |byte| {
        if (byte == 0) {
            encoded[encoded_len] = alphabet[0];
            encoded_len += 1;
        } else {
            break;
        }
    }

    // Reverse the encoded result (Base58 is big-endian)
    for (0..encoded_len / 2) |i| {
        const j = encoded_len - i - 1;
        const temp = encoded[i];
        encoded[i] = encoded[j];
        encoded[j] = temp;
    }

    return encoded[0..encoded_len];
}
