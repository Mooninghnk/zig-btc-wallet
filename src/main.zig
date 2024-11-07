const std = @import("std");
const secp2 = @import("sepc");
const rand = std.crypto.random;
const print = std.debug.print;
const webui = @import("webui");

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

    const prvires: [66]u8 = privkey.toString();

    const wk = alloc.dupeZ(u8, &res) catch unreachable;

    defer alloc.free(wk);

    const stx = std.fmt.allocPrintz(alloc, "Private key: {s} \n Pubkey {s}", .{ res, prvires }) catch unreachable;

    print("{s}", .{res});

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
