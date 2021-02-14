package crypto

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestHkdfSha1(t *testing.T) {
	type args struct {
		key  []byte
		salt []byte
		info []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "[key=1]",
			args: args{
				key: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
					1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				salt: []byte("12345678123456781234567812345678"),
				info: []byte("ss-subkey"),
			},
			want: []byte{128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199,
				245, 55, 99, 251, 53, 56, 225, 92, 92, 5, 94,
				252, 21, 4, 211, 164, 43, 251, 44, 61, 208},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HkdfSha1(tt.args.key, tt.args.salt, tt.args.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("HkdfSha1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HkdfSha1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIncrement(t *testing.T) {
	type args struct {
		num []byte
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "[num=0]",
			args: args{
				num: []byte{0, 0},
			},
		},
		{
			name: "[num=1]",
			args: args{
				num: []byte{1, 0},
			},
		},
		{
			name: "[num=255]",
			args: args{
				num: []byte{255, 0},
			},
		},
		{
			name: "[num=256]",
			args: args{
				num: []byte{0, 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := binary.LittleEndian.Uint16(tt.args.num)
			Increment(tt.args.num)
			after := binary.LittleEndian.Uint16(tt.args.num)

			if !reflect.DeepEqual(before+1, after) {
				t.Errorf("After Increment(), num = %v, want %v", after, before+1)
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	type args struct {
		password []byte
		keySize  int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "[password=\"hehe\"]",
			args: args{
				password: []byte("hehe"),
				keySize:  32,
			},
			want: []byte{82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136,
				182, 52, 104, 130, 106, 109, 81, 225, 207, 24, 87,
				148, 16, 101, 57, 172, 239, 219, 100, 183, 95},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeriveKey(tt.args.password, tt.args.keySize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeriveKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
