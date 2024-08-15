package util

func FilterArray[T any](ss []T, test func(T) bool) (ret []T) {
	for _, s := range ss {
		if test(s) {
			ret = append(ret, s)
		}
	}
	return
}

func RemoveFromArray[T any](ss []T, idx int) []T {
	return append(ss[:idx], ss[idx+1:]...)
}
