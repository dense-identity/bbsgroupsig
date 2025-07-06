## Optimizing Pairing Computations in BBS Group Signatures

The derivation relies on two fundamental properties of bilinear pairings:
1.  **Exponent Property:** $e(P, Q)^a = e(aP, Q)$
2.  **Multiplication Property:** $e(P_1, Q) \cdot e(P_2, Q) = e(P_1 + P_2, Q)$

---
### ## Step 1: Start with the Original Formula
The initial computation for $R_3$ involves three separate pairing operations:
$$R_3 = e(T_3, g_2)^{r_x} \cdot e(h, w)^{-(r_\alpha + r_\beta)} \cdot e(h, g_2)^{-(r_{\delta_1} + r_{\delta_2})}$$

---
### ## Step 2: Apply the Exponent Property
We move the exponent from outside each pairing to inside the first argument as a scalar multiplication.

* $e(T_3, g_2)^{r_x}$ becomes $e(r_x T_3, \ g_2)$
* $e(h, w)^{-(r_\alpha + r_\beta)}$ becomes $e(-(r_\alpha + r_\beta)h, \ w)$
* $e(h, g_2)^{-(r_{\delta_1} + r_{\delta_2})}$ becomes $e(-(r_{\delta_1} + r_{\delta_2})h, \ g_2)$

Now, our equation looks like this:
$$R_3 = e(r_x T_3, \ g_2) \cdot e(-(r_\alpha + r_\beta)h, \ w) \cdot e(-(r_{\delta_1} + r_{\delta_2})h, \ g_2)$$

---
### ## Step 3: Apply the Multiplication Property
Next, we identify the terms that share the same second argument in the pairing. In this case, two terms share $g_2$. We can combine them into a single pairing.

We group the terms with $g_2$:
$$[e(r_x T_3, \ g_2) \cdot e(-(r_{\delta_1} + r_{\delta_2})h, \ g_2)] \cdot e(-(r_\alpha + r_\beta)h, \ w)$$

Using the multiplication property, the part in the brackets becomes:
$$e(r_x T_3 - (r_{\delta_1} + r_{\delta_2})h, \ g_2)$$

---
### ## Step 4: Arrive at the Final Simplified Formula
By substituting the combined term back into the equation, we get the final, optimized formula, which now only requires two pairing computations.

$$R_3 = e(r_x T_3 - (r_{\delta_1} + r_{\delta_2})h, \ g_2) \cdot e(-(r_\alpha + r_\beta)h, \ w)$$

This reduces the computational workload by trading one expensive pairing operation for a few much faster scalar multiplications and point additions.