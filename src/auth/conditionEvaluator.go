package auth

import (
	"errors"
	"fmt"
	"github.com/araddon/dateparse"
	"github.com/gobwas/glob"
	"github.com/lars250698/graphql-iam/src/model"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ConditionEvaluator struct {
	condition model.Condition
	request   http.Request
	variables map[string]interface{}
	query     string
	claims    map[string]interface{}
}

func (ce *ConditionEvaluator) Evaluate() bool {
	for key, value := range ce.condition {
		res := false
		switch key {
		case "StringEquals":
			res = ce.stringEquals(value)
			break
		case "StringNotEquals":
			res = ce.stringNotEquals(value)
			break
		case "StringEqualsIgnoreCase":
			res = ce.stringEqualsIgnoreCase(value)
			break
		case "StringNotEqualsIgnoreCase":
			res = ce.stringNotEqualsIgnoreCase(value)
			break
		case "StringLike":
			res = ce.stringLike(value)
			break
		case "StringNotLike":
			res = ce.stringNotLike(value)
			break
		case "DateEquals":
			res = ce.dateEquals(value)
			break
		case "DateNotEquals":
			res = ce.dateNotEquals(value)
			break
		case "DateLessThan":
			res = ce.dateLessThan(value)
			break
		case "DateLessThanEquals":
			res = ce.dateLessThanEquals(value)
			break
		case "DateGreaterThan":
			res = ce.dateGreaterThan(value)
			break
		case "DateGreaterThanEquals":
			res = ce.dateGreaterThanEquals(value)
			break
		case "NumericEquals":
			res = ce.numericEquals(value)
			break
		case "NumericLessThan":
			res = ce.numericLessThan(value)
			break
		case "NumericLessThanEquals":
			res = ce.numericLessThanEquals(value)
			break
		case "NumericGreaterThan":
			res = ce.numericGreaterThan(value)
			break
		case "NumericGreaterThanEquals":
			res = ce.numericGreaterThanEquals(value)
			break
		case "Bool":
			res = ce.bool_(value)
			break
		case "Null":
			res = ce.null_(value)
			break
		case "IpAddress":
			res = ce.ipAddress(value)
			break
		case "NotIpAddress":
			res = ce.notIpAddress(value)
			break
		}
		if !res {
			return false
		}
	}

	return true
}

func (ce *ConditionEvaluator) resolveMatchingReceiver(receiverStr string) (interface{}, error) {
	before, after, found := strings.Cut(receiverStr, ":")
	if !found {
		return nil, errors.New(fmt.Sprintf("condition receiver %s is invalid", receiverStr))
	}
	switch before {
	case "header":
		return ce.request.Header.Get(after), nil
	case "var":
		return ce.variables[after], nil
	case "jwt":
		return ce.claims[after], nil
	case "request":
		return getHttpMatchingReceiverValue(after, ce.request)
	case "meta":
		return getMetaMatchingReceiverValue(after)
	}
	return nil, errors.New(fmt.Sprintf("condition receiver %s is invalid", receiverStr))
}

func getHttpMatchingReceiverValue(key string, req http.Request) (interface{}, error) {
	switch key {
	case "proto":
		return req.Proto, nil
	case "remoteAddr":
		ipWithPort := req.Header.Get("X-Forwarded-For")
		if ipWithPort == "" {
			ipWithPort = req.RemoteAddr
		}
		host, _, err := net.SplitHostPort(ipWithPort)
		return host, err
	case "port":
		ipWithPort := req.Header.Get("X-Forwarded-For")
		if ipWithPort == "" {
			ipWithPort = req.RemoteAddr
		}
		_, port, err := net.SplitHostPort(ipWithPort)
		return port, err
	}
	return nil, errors.New("could not resolve http matching receiver")
}

func getMetaMatchingReceiverValue(key string) (interface{}, error) {
	switch key {
	case "time_unix":
		return time.Now().Unix(), nil
	case "time":
		return time.Now(), nil
	}
	return nil, errors.New("could not resolve meta matching receiver")
}

func (ce *ConditionEvaluator) stringEquals(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		if value != receiver {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) stringNotEquals(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		if value == receiver {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) stringEqualsIgnoreCase(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		if !strings.EqualFold(value, receiver) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) stringNotEqualsIgnoreCase(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		// double negation to keep consistency
		// negate wanted condition for better readability
		if strings.EqualFold(value, receiver) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) stringLike(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		g, err := glob.Compile(value)
		if err != nil {
			return false
		}

		if !g.Match(receiver) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) stringNotLike(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		g, err := glob.Compile(value)
		if err != nil {
			return false
		}

		if g.Match(receiver) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) dateEquals(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		compareWith, err := dateparse.ParseAny(value)
		if err != nil {
			return false
		}

		receiver, err := getReceiverDate(receiverInterface)

		if err != nil || !receiver.Equal(compareWith) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) dateNotEquals(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		compareWith, err := dateparse.ParseAny(value)
		if err != nil {
			return false
		}

		receiver, err := getReceiverDate(receiverInterface)

		if err != nil || receiver.Equal(compareWith) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) dateLessThan(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		compareWith, err := dateparse.ParseAny(value)
		if err != nil {
			return false
		}

		receiver, err := getReceiverDate(receiverInterface)

		if err != nil || !receiver.Before(compareWith) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) dateLessThanEquals(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		compareWith, err := dateparse.ParseAny(value)
		if err != nil {
			return false
		}

		receiver, err := getReceiverDate(receiverInterface)

		if err != nil || !(receiver.Equal(compareWith) || receiver.Before(compareWith)) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) dateGreaterThan(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		compareWith, err := dateparse.ParseAny(value)
		if err != nil {
			return false
		}

		receiver, err := getReceiverDate(receiverInterface)

		if err != nil || !receiver.After(compareWith) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) dateGreaterThanEquals(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		compareWith, err := dateparse.ParseAny(value)
		if err != nil {
			return false
		}

		receiver, err := getReceiverDate(receiverInterface)

		if err != nil || !(receiver.Equal(compareWith) || receiver.After(compareWith)) {
			return false
		}
	}
	return true
}

func getReceiverDate(receiverInterface interface{}) (time.Time, error) {
	switch receiverInterface.(type) {
	case string:
		receiver, err := dateparse.ParseAny(receiverInterface.(string))
		if err != nil {
			return time.Time{}, errors.New("could not parse receiver as date")
		}
		return receiver, nil
	case int64:
		return time.Unix(receiverInterface.(int64), 0), nil
	case int:
		return time.Unix(int64(receiverInterface.(int)), 0), nil
	case int32:
		return time.Unix(int64(receiverInterface.(int32)), 0), nil
	case time.Time:
		return receiverInterface.(time.Time), nil
	default:
		return time.Time{}, errors.New("could not parse receiver as date")
	}
}

func (ce *ConditionEvaluator) numericEquals(params model.ConditionParams) bool {
	for key, value := range params {
		target, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}

		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, err := getReceiverNum(receiverInterface)

		if err != nil || !(receiver == target) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) numericLessThanEquals(params model.ConditionParams) bool {
	for key, value := range params {
		target, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}

		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, err := getReceiverNum(receiverInterface)

		if err != nil || !(receiver >= target) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) numericGreaterThanEquals(params model.ConditionParams) bool {
	for key, value := range params {
		target, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}

		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, err := getReceiverNum(receiverInterface)

		if err != nil || !(receiver >= target) {
			return false
		}
	}
	return true

}

func (ce *ConditionEvaluator) numericLessThan(params model.ConditionParams) bool {
	for key, value := range params {
		target, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}

		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, err := getReceiverNum(receiverInterface)

		if err != nil || !(receiver < target) {
			return false
		}
	}
	return true

}

func (ce *ConditionEvaluator) numericGreaterThan(params model.ConditionParams) bool {
	for key, value := range params {
		target, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}

		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, err := getReceiverNum(receiverInterface)

		if err != nil || !(receiver > target) {
			return false
		}
	}
	return true
}

func getReceiverNum(receiverInterface interface{}) (float64, error) {
	switch receiverInterface.(type) {
	case string:
		receiver, err := strconv.ParseFloat(receiverInterface.(string), 64)
		if err != nil {
			return -1, errors.New("could not parse receiver as numeric")
		}
		return receiver, nil
	case int:
		return float64(receiverInterface.(int)), nil
	case float32:
		return float64(receiverInterface.(float32)), nil
	case float64:
		return receiverInterface.(float64), nil
	default:
		return -1, errors.New("could not parse receiver as numeric")
	}
}

func (ce *ConditionEvaluator) bool_(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		r, err := strconv.ParseBool(receiver)
		if err != nil {
			return false
		}

		v, err := strconv.ParseBool(value)
		if err != nil {
			return false
		}

		if r != v {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) null_(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		shouldBeNull, err := strconv.ParseBool(value)
		if err != nil {
			return false
		}

		if !((receiverInterface == nil) && shouldBeNull) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) ipAddress(params model.ConditionParams) bool {
	for key, value := range params {

		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		if !ipOrCidrMatch(value, receiver) {
			return false
		}
	}
	return true
}

func (ce *ConditionEvaluator) notIpAddress(params model.ConditionParams) bool {
	for key, value := range params {
		receiverInterface, err := ce.resolveMatchingReceiver(key)
		if err != nil {
			return false
		}

		receiver, ok := receiverInterface.(string)
		if !ok {
			return false
		}

		if ipOrCidrMatch(value, receiver) {
			return false
		}
	}
	return true
}

func ipOrCidrMatch(ipOrCidrStr string, ipStr string) bool {
	ip := net.ParseIP(ipStr)

	_, ipOrCidr, err := net.ParseCIDR(ipOrCidrStr)
	if err != nil {
		return net.ParseIP(ipOrCidrStr).Equal(ip)
	}

	return ipOrCidr.Contains(ip)
}
