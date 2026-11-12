-- Deterministic Lua workload for tests/run-examples.sh: strings, tables, closures, coroutines, errors, floats, GC.
local out = {}
local function p(...) local t = {} for i = 1, select('#', ...) do t[#t+1] = tostring((select(i, ...))) end out[#out+1] = table.concat(t, " ") end

-- integers and floats
local s = 0 for i = 1, 100000 do s = s + i * i % 7 end p("int", s)
local f = 0.0 for i = 1, 2000 do f = f + math.sin(i) * math.sqrt(i) / (1 + math.exp(-i / 300)) end p("float", string.format("%.10f", f))
p("math", math.floor(-3.5), math.ceil(-3.5), math.fmod(7, -3), 7 // 2, -7 // 2, 2^53 + 1, math.maxinteger + 0.0, 1e300 * 1e10, -(0/0) ~= -(0/0))
p("fmt", string.format("%5.2f|%-6d|%x|%q|%g|%g", 3.14159, 42, 255, "a\nb", 1e-7, 123456789.0))

-- strings and patterns
local words = {} for w in ("the quick brown fox jumps over the lazy dog"):gmatch("%a+") do words[#words+1] = w:upper() end
p("words", table.concat(words, ","))
p("gsub", (("hello world from lua"):gsub("(%w+)", "<%1>")))
p("rep", #(("ab"):rep(10000)), ("x"):rep(3, "-"), ("abc"):byte(1, -1))

-- tables, sorting, metatables
local t = {} math.randomseed(42) for i = 1, 5000 do t[i] = math.random(1, 1000000) end
table.sort(t) p("sort", t[1], t[2500], t[5000])
local V = {} V.__index = V V.__add = function(a, b) return setmetatable({x = a.x + b.x, y = a.y + b.y}, V) end
V.__tostring = function(v) return "(" .. v.x .. "," .. v.y .. ")" end
local acc = setmetatable({x = 0, y = 0}, V) for i = 1, 100 do acc = acc + setmetatable({x = i, y = -i}, V) end p("meta", acc)

-- closures and recursion
local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end p("fib", fib(25))
local function counter() local c = 0 return function() c = c + 1 return c end end
local c1, c2 = counter(), counter() c1() c1() p("closure", c1(), c2())

-- coroutines
local gen = coroutine.wrap(function() for i = 1, 5 do coroutine.yield(i * i) end end)
local sq = {} for _ = 1, 5 do sq[#sq+1] = gen() end p("coro", table.concat(sq, " "))

-- errors (setjmp/longjmp in the C core)
local ok, err = pcall(function() error({code = 7}) end) p("pcall", ok, type(err), err.code)
local ok2, err2 = pcall(function() local x = nil; return x.y end) p("pcall2", ok2, (err2:gsub("^.-:%d+: ", "")))
p("xpcall", xpcall(function() error("boom", 0) end, function(m) return "handled " .. m end))

-- garbage collection under load
local keep = {} for i = 1, 200000 do local s = tostring(i) .. "x" if i % 1000 == 0 then keep[#keep+1] = s end end
collectgarbage() p("gc", #keep, keep[#keep])

-- utf8 and string.pack
p("utf8", utf8.len("häöü€"), utf8.char(72, 228, 8364))
p("pack", #string.pack("<i4 d s1", 7, 1.5, "hi"), string.unpack("<i4", string.pack("<i4", -2)))

-- file I/O
local fn = "lua-test.tmp"
local fh = assert(io.open(fn, "w")) for i = 1, 1000 do fh:write(i, "\n") end fh:close()
local n, sum = 0, 0 for line in io.lines(fn) do n = n + 1 sum = sum + tonumber(line) end os.remove(fn) p("io", n, sum)

for _, l in ipairs(out) do print(l) end
os.exit(3)
