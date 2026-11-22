package main

import "fmt"

type Job struct {
	Length     int
	FirstIndex int
}

func Jobs(cfg Config) []Job {
	jobs := make([]Job, 0, (cfg.MaxLength-cfg.MinLength+1)*len(cfg.Charset.Symbols))

	for length := cfg.MinLength; length <= cfg.MaxLength; length++ {
		for first := range cfg.Charset.Symbols {
			jobs = append(jobs, Job{Length: length, FirstIndex: first})
		}
	}

	return jobs
}

type Cursor struct {
	charset []byte
	storage []byte
	length  int
	indexes []int
	done    bool
}

func NewCursor(charset []byte, job Job, storage []byte) (Cursor, error) {
	if len(charset) == 0 || job.Length < 1 || job.FirstIndex < 0 || job.FirstIndex >= len(charset) || len(storage) < job.Length {
		return Cursor{}, fmt.Errorf("invalid cursor")
	}

	indexes := make([]int, job.Length)
	indexes[0] = job.FirstIndex
	storage[0] = charset[job.FirstIndex]

	for i := 1; i < job.Length; i++ {
		storage[i] = charset[0]
	}

	return Cursor{charset: charset, storage: storage, length: job.Length, indexes: indexes}, nil
}

func (c *Cursor) Value() []byte {
	return c.storage[:c.length]
}

func (c *Cursor) Next() bool {
	if c.done || c.length == 1 {
		c.done = true

		return false
	}

	for i := c.length - 1; i >= 1; i-- {
		if c.indexes[i]+1 < len(c.charset) {
			c.indexes[i]++

			c.storage[i] = c.charset[c.indexes[i]]

			return true
		}

		c.indexes[i] = 0
		c.storage[i] = c.charset[0]
	}

	c.done = true

	return false
}
