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
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

export function updateAddress () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })

    const updateFields = {
      fullName: req.body.fullName,
      mobileNum: req.body.mobileNum,
      zipCode: req.body.zipCode,
      streetAddress: req.body.streetAddress,
      city: req.body.city,
      state: req.body.state,
      country: req.body.country
    }

    if (address != null) {
      await address.update(updateFields)
    }
    res.status(200).json({ status: 'success', data: updateFields })
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
  }
}
