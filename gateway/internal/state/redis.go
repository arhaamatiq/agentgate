package state

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const sessionTTL = 24 * time.Hour

type Redis struct {
	c *redis.Client
}

func NewRedis(url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	opt.DialTimeout = 2 * time.Second
	opt.ReadTimeout = 500 * time.Millisecond
	opt.WriteTimeout = 500 * time.Millisecond
	opt.PoolSize = 64
	return &Redis{c: redis.NewClient(opt)}, nil
}

func historyKey(s string) string { return "ag:hist:" + s }
func cacheKey(s string) string   { return "ag:judge:" + s }
func rateKey(s string) string    { return "ag:rate:" + s }

func (r *Redis) History(ctx context.Context, session string, n int) ([]HistoryEntry, error) {
	raw, err := r.c.LRange(ctx, historyKey(session), int64(-n), -1).Result()
	if err != nil {
		return nil, err
	}
	out := make([]HistoryEntry, 0, len(raw))
	for _, s := range raw {
		var e HistoryEntry
		if err := json.Unmarshal([]byte(s), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (r *Redis) AppendHistory(ctx context.Context, session string, e HistoryEntry, keep int) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	k := historyKey(session)
	pipe := r.c.Pipeline()
	pipe.RPush(ctx, k, b)
	pipe.LTrim(ctx, k, int64(-keep), -1)
	pipe.Expire(ctx, k, sessionTTL)
	_, err = pipe.Exec(ctx)
	return err
}

func (r *Redis) CacheGet(ctx context.Context, key string) (*CachedVerdict, error) {
	b, err := r.c.Get(ctx, cacheKey(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v CachedVerdict
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *Redis) CacheSet(ctx context.Context, key string, v CachedVerdict, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return r.c.Set(ctx, cacheKey(key), b, ttl).Err()
}

// Sliding-window log in a sorted set, evaluated atomically server-side.
var slidingWindow = redis.NewScript(`
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], window)
return redis.call('ZCARD', KEYS[1])
`)

func (r *Redis) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	now := time.Now().UnixMilli()
	n, err := slidingWindow.Run(ctx, r.c, []string{rateKey(key)},
		now, window.Milliseconds(), itoa(now)+"-"+uuid.NewString()).Int()
	if err != nil {
		return false, err
	}
	return n <= limit, nil
}

func (r *Redis) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }
func (r *Redis) Close() error                   { return r.c.Close() }
