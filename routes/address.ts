/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

export function getAddress () {
  return async (req: Request, res: Response) => {
    const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function updateAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address == null) {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
      return
    }

    try {
      const updatedFields: Record<string, unknown> = {}
      if (req.body.fullName !== undefined) updatedFields.fullName = req.body.fullName
      if (req.body.mobileNum !== undefined) updatedFields.mobileNum = req.body.mobileNum
      if (req.body.zipCode !== undefined) updatedFields.zipCode = req.body.zipCode
      if (req.body.streetAddress !== undefined) updatedFields.streetAddress = req.body.streetAddress
      if (req.body.city !== undefined) updatedFields.city = req.body.city
      if (req.body.state !== undefined) updatedFields.state = req.body.state
      if (req.body.country !== undefined) updatedFields.country = req.body.country

      await address.update({
        ...updatedFields
      })
      res.status(200).json({ status: 'success', data: address })
    } catch {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
