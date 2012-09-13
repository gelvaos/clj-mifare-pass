(ns clj-mifare-pass.pass
  (:import [javax.crypto Cipher SecretKey SecretKeyFactory]
           [javax.crypto.spec DESedeKeySpec]))

(defn hexstr2bytes [s]
  (vec (map #(Integer/parseInt % 16) (map #(apply str %) (partition 2 s)))))

(defn bytes2hexstr [bytes]
  (apply str
         (map #(.toUpperCase %)
              (map #(format "%02x" %)
                   (map #(bit-and 0xFF %) (seq bytes))))))


(defn byte-bit-shift-left [b num-bits]
  (bit-and (bit-shift-left b num-bits) 0xFF))

(defn get-d-key-a [key-a]
  (if (not= 6 (count key-a)) (throw (Exception. "Incorrect KeyA length.")))
  (let [d-key-a (transient [])]
    (reduce #(conj! %1 (byte-bit-shift-left %2 1)) d-key-a key-a) ; make bitwise shifts
    (conj! d-key-a 0) (conj! d-key-a 0) ; make key 8 bytes
    (loop [ka key-a b 6]
      (when (> b 0)
        (let [x (first ka)]
          (assoc! d-key-a 6
                  (bit-or (nth d-key-a 6)
                          (byte-bit-shift-left
                           (bit-shift-right (bit-and x 0xFF) 7)
                           b)))
          (recur (rest ka) (dec b)))))
    (persistent! d-key-a)))

(defn get-d-key-b [key-b]
  (if (not= 6 (count key-b)) (throw (Exception. "Incorrect KeyA length.")))
  (let [d-key-b (transient [])]
    (conj! d-key-b 0) (conj! d-key-b 0) ; add precendent 2 bytes
    (reduce #(conj! %1 (byte-bit-shift-left %2 1)) d-key-b key-b) ; make bitwise shifts
    (loop [kb (reverse key-b) b 6]
      (when (> b 0)
        (let [x (first kb)]
          (assoc! d-key-b 1
                  (bit-or (nth d-key-b 1)
                          (byte-bit-shift-left
                           (bit-shift-right (bit-and x 0xFF) 7)
                           b)))
          (recur (rest kb) (dec b)))))
    (persistent! d-key-b)))

(defn- get-byte-array [a]
  (into-array Byte/TYPE
              (map #(.byteValue %) a)))

(defn- gen-encryption-key [d-key-a d-key-b]
  (get-byte-array (concat (reverse d-key-a) (reverse d-key-b) (reverse d-key-a))))


(defn get-mifare-pass [d-key-a d-key-b]
  (let [
        tdes-key (gen-encryption-key d-key-a d-key-b)
        start-data (make-array Byte/TYPE 8)
        kf (SecretKeyFactory/getInstance "DESede")
        encipher (Cipher/getInstance "DESede/ECB/NoPadding")
        des-key (DESedeKeySpec. tdes-key)
        secret-key (. kf generateSecret des-key)
        ]
    (. encipher init Cipher/ENCRYPT_MODE secret-key)
    (vec (reverse (. encipher doFinal start-data 0 8)))))


